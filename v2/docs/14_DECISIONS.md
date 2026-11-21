---
id: V2-014
classification: public
title: Decisions (ADR record)
audience: technical
owner: credmgr-v2
status: needs-verification
export_allowed: true
surface: repo
last_reviewed: 2026-08-18
---

<!-- artifact-hardened: NEEDS RE-HARDENING — an append-only decision record, not a specification, so it is NOT rewritten
     to "ultimate destination" state: rewriting a past decision would falsify the record it exists to
     be. ADR-057 was contributed by the parallel Track B session and ADR-058/059/060 appended by
     Session 21, all on 2026-08-18, which is why the previous stamp (@ 98a03d7) no longer matches
     this body.
     Two wording changes were also made in ADR-019 and its rejected alternative: the two loopback
     address literals they used were replaced by the concept each named ("loopback HTTP daemon",
     "loopback-bound static server"). docgen's Gate 3b blocks those literals, so the record could
     not build at all otherwise — and this note cannot quote them either, for the same reason. No decision, rationale or outcome was altered —
     the change is recorded here so an edit to a record is auditable rather than silent. -->
<!-- Supersedes: Approved With Known Risks @ 6ee1e5f on 2026-08-10 (pass 2 content +
     reconciliation delta diff-verified, ADR-052; that stamp only accounted for ADR-052).
     Three ADR sections landed in three later commits with no re-stamp at the time: ADR-053
     (c39888a, Phase 8 audit — the node.restore cross-node authorization fix, unrelated to
     org vault work) and ADR-054/ADR-055 (98a03d7, Backend-finish session — maintenance.verify
     |doctor|backup and entry.undo). Each was independently evidenced and reviewed by its own
     authoring session (see PHASE8_AUDIT_REPORT.md for ADR-053; BUILD_LOG.md Session 17 for
     ADR-054/055) — this stamp update reconciles the header to the real commit, per the same
     "stamp reconciliation, not a fresh audit" scope ADR-052 itself used, rather than re-running
     an independent adversarial review of the file's full ~1,850 lines. Found and fixed during
     the 2026-08-17 full-sweep pass. -->
# Decision log

`CredMgr V2` · Pass 1 · `2026-08-04`

Every non-obvious choice, with the alternative that was rejected and why. A decision recorded
without its rejected alternative is not a decision, it is an assertion.

---

## ADR-001 · A broker process is the single enforcement point

**Context.** V1 has three independent paths to plaintext (CLI, HTTP daemon, MCP), each with
its own authorisation idea. `CLAUDE.md` documents the consequence: agent calls bypass the PIN.
**Decision.** One long-running `credmgrd`. Everything else is a client over a Unix socket.
**Rejected.** Keeping direct-decrypt clients with a shared policy library — a library can be
bypassed by importing around it; a process cannot.
**Cost.** A daemon to manage, a socket protocol to version, an always-on process holding keys.
**Consequence.** Node isolation is enforceable at all. Without this ADR the rest is decoration.

## ADR-002 · Per-node asymmetric keys

**Decision.** Each node holds an X25519 keypair; public half in the plaintext registry.
**Rejected.** One vault key + broker-side filtering (isolation would be UI-deep, and a disk
image would still expose everything). Per-node *symmetric* keys (no write-while-locked, no
write-without-read).
**Consequence.** Real at-rest separation; add-to-locked-vault; write-only agent scopes.

## ADR-003 · Grants are broker-enforced, not cryptographic

**Decision.** A grant is a signed registry entry the broker checks. It does not wrap A's key
to B.
**Rejected.** Cryptographic grants — they survive a broker bypass, but revocation then means
re-keying and re-encrypting the whole source node, so a revoked grant is really a copy someone
already took.
**Consequence.** Instant revocation. **If the broker is compromised, grants mean nothing** —
stated in `05 §6 AR-4` rather than smoothed over.

## ADR-004 · Depth is capped at 2

**Decision.** Global (0) → project (1) → sub-node (2). No deeper.
**Rejected.** Arbitrary depth — the access matrix becomes unauditable, the graph unreadable,
and "which ancestor granted this?" becomes a research question.
**Reversal cost.** Low: `depth` widens and R4 already walks the full ancestor chain.

## ADR-005 · Upward read only; parents do not read children

**Decision.** `descendantRead: false` by default, per-node opt-in.
**Rejected.** Parent-reads-child by default (intuitive, and wrong the moment a sub-node is
`prod`).
**Consequence.** A parent node is an *organising* node, not a superuser.

## ADR-006 · Depth-2 siblings share; depth-1 projects never do

**Decision.** `siblingVisibility: 'shared'` default on depth-1 parents; permanently
`'isolated'` on Global.
**Source.** The brief: *"Projects X and Y must be interconnected."*
**Consequence.** The surprising half (sharing) is configurable; the load-bearing half
(top-level isolation) is not editable in the UI at all.

## ADR-007 · Removal seals, never deletes

**Decision.** Node removal re-encrypts entries to the orphan key. Names stay; values need a
human, a biometric and a fresh TOTP, every time.
**Rejected.** Hard delete with a confirmation (irreversible operator error is a P0 threat);
soft delete with a flag (a flag is not a boundary — a bug flips it).
**Consequence.** "Destroy" exists, once, at the very end, with a 10-second cooling delay.

## ADR-008 · ~~Node.js 22, zero runtime dependencies in the core~~ · **SUPERSEDED by `16_CROSS_PLATFORM.md` (2026-08-05)**

> The core is **Rust**. This ADR is kept for the reasoning trail only. V1 remains Node.

**Decision.** `node:crypto` covers X25519, HKDF-SHA-512, ChaCha20-Poly1305, scrypt.
**Rejected.** Rust (ADR-009), Go, keeping the `age` binary on the hot path (plaintext through
a pipe, temp identity files, a Homebrew dependency).
**Cost.** No reliable heap zeroisation (`05 §6 AR-3`).

## ADR-009 · ~~A Rust broker is deferred~~ · **RESOLVED — ADOPTED (2026-08-05)**

> Its stated trigger was "the vault leaves this machine". Shipping publicly to Windows and
> Linux users *is* that trigger. See `16_CROSS_PLATFORM.md §8`.

**Trigger for revisiting:** the vault leaves this machine, gains a network surface, or holds
material whose exposure is unrecoverable beyond what it holds today.
**Why not now:** it discards a working 15k-line codebase, the operator's ability to read it,
and roughly a month, to buy protection against A6/A8 — the two lowest-priority adversaries.

## ADR-010 · The registry is plaintext

**Decision.** Node names, shape, grants and counts are unencrypted, HMAC-signed.
**Why.** The graph must draw while locked, and a vault you cannot survey while locked is a
vault people leave unlocked.
**Cost.** `05 §6 AR-1`. **Resolved by ADR-029:** names stay plaintext by default, with a
per-node `privateNames` opt-out for wallet-class nodes.

## ADR-011 · Predefined field schemas are deleted outright

**Decision.** No `TYPE_SCHEMAS`, no field-name vocabulary, free-text labels only.
**Rejected.** Keeping schemas as optional suggestions — an optional schema still trains the
UI to nag, and V1 proved it.
**Preserved.** Migration keeps every label the operator ever typed (`11 §3`).

## ADR-012 · Type inference suggests; it never decides

**Decision.** Inference sets a chip and a mask default, both one click from being overridden.
It never rewrites, trims, reformats or rejects a value.
**Rejected.** Validation-on-save — a credential manager that refuses your credential because
it does not match a regex is worse than useless.

## ADR-013 · `///` separates fields; a preview toggle splits entries

**Decision.** Bulk paste creates one entry with many fields. A preview toggle turns each
`///` segment into its own entry.
**Why.** The brief is ambiguous ("credentials are separate"). Both readings are supported and
the preview shows which one you are getting before saving.

**Built (ADR-078, 2026-10).** Multi-field entries exist: one entry is one field document sealed as
envelope version 2, the labels are kept, and the split toggle is one `entry.create_batch` item per `///`
segment (the parser keeps the segment boundaries, `parse_bulk_segments`).

## ADR-014 · "Label, colon, **space**, value"

**Decision.** A line is labelled only when the first colon is followed by a space and the
prefix is not a URI scheme.
**Rejected.** Splitting on any colon — it destroys `host:5432` and every URL.

## ADR-015 · Operations leave the search bar

**Decision.** Search finds nodes and entries only. Operations live in their own Pro panel.
Lite has no Operations panel and one search action.
**Source.** The brief, verbatim.
**Principle.** Lite hides levers, never safety: backup and integrity checking run in both
modes.

## ADR-016 · The inspector shows one node's own entries, full stop

**Decision.** No inherited section, no "reachable from here", no merged view.
**Rejected.** A collapsed "inherited" group — convenient, and it reintroduces exactly the
contamination the product exists to prevent. Mixing "what lives here" with "what I could
reach" is how the wrong secret gets rotated.

## ADR-017 · Two 2FA concepts, two names, never one word

**Decision.** **Gate 2FA** protects the vault/nodes. **TOTP items** are stored seeds.
The hover card's second number counts TOTP items; gate status is a glyph, not a number.
**Consequence.** The card keeps exactly two numbers, as instructed.

## ADR-018 · An agent can get a TOTP code, never a seed

**Decision.** `credmgr_totp_code` returns 6 digits. No API path returns a seed to a
non-native transport.
**Why.** A leaked code is worth 30 seconds; a leaked seed is worth forever.

## ADR-019 · No HTTP surface at all

**Decision.** V1's loopback HTTP daemon is removed. The UI is static files over a UDS.
**Why.** A bound port is reachable by any process and, with a mistake in CORS or CSP, by a
web page. A credential vault should not be one misconfiguration from a browser.

## ADR-020 · One global MCP registration, cwd-scoped

**Decision.** Keep the single `mcpServers.credmgr` entry in `~/.claude.json`; the broker maps
the client's cwd to a node.
**Rejected.** Per-project MCP entries (N configs to drift, and a new project starts unscoped).
**Consequence.** One config line, N boundaries. `05 §6 AR-5`: cwd is spoofable, so the token
is the authority and cwd is an audit signal.

## ADR-021 · Denials are explicit and carry a remedy

**Decision.** A cross-node request returns a structured denial naming subject, target, rule
and the human action that would fix it. Never an empty list.
**Why.** Empty means "nothing there"; denied means "not yours". Conflating them teaches an
agent to retry until something works.

## ADR-022 · Svelte 5, no Tailwind, vendored graph engine

**Decision.** See `02 §5`.
**Rejected.** React (bundle + reconciler fighting a canvas), vanilla (V1's 4,589-line
`app.js` is what we are escaping), Tailwind (a second source of truth beside KEEP tokens),
any CDN-loaded library (offline + CSP).

---

## Added by Pass 2

## ADR-023 · `write` is split into `create` and `update`

**Context.** ADR-002's asymmetric node keys let anyone encrypt to a node's public key. Pass 1
sold that as "write without read". It is also **credential substitution**: overwrite a
credential with one you control, produce perfectly valid ciphertext, and the operator
authenticates to your server.
**Decision.** `create` (new name) is permitted while locked and lands in a review tray.
`update` requires the vault unlocked.
**Rejected.** Signing writes with a client key (needs a client PKI and still permits a
compromised client to substitute); dropping write-while-locked entirely (loses the feature
that stops people leaving the vault open all day).
**Consequence.** The useful half survives; the attack does not.

## ADR-024 · Freshness is enforced outside the vault directory

**Context.** An HMAC proves authorship, not recency. A validly-signed *older* registry
reinstates revoked grants.
**Decision.** A monotonic `vaultGeneration` in the macOS Keychain, mirrored in the SE-wrapped
root blob. Lower generation ⇒ refuse to open.
**Rejected.** A generation inside the file (rolls back with it); wall-clock timestamps
(spoofable, and clock drift is already a known problem — see F-17).
**Cost.** One more piece of state that can desynchronise; `doctor --rebuild-registry` is the
documented repair.

## ADR-025 · The vault has no listening socket at all

**Decision.** The native shell serves the UI via `WKURLSchemeHandler` from the app bundle. The
Vite dev server is development-only and refuses to run against a real vault.
**Rejected.** A loopback-bound static server — reachable by every local process, and the seam
along which an "API endpoint, just for the UI" eventually appears.

## ADR-026 · Approval on demand instead of an agent unlock window

**Context.** A 15-minute auto-lock interrupts hour-long agent runs.
**Decision.** No agent bypass. A locked-vault reveal returns `approval_pending` and raises a
notification; one Touch ID tap releases one value; the vault stays locked.
**Rejected.** A long agent session TTL (recreates the permanently-open vault); auto-approving
for a trusted node (an agent's trust is exactly what is in question).
**Consequence.** The operator sees *what* is being asked for at the moment it is asked — the
highest-value security signal in the system, for the price of one tap.

## ADR-027 · Restore is a move from a retained archive, not an unseal

**Context.** Pass 1 discarded originals at seal time and separately promised a 7-day one-click
restore. Restoring from the orphan copy would have cost a biometric prompt and a fresh TOTP
code *per item*.
**Decision.** Sealing retains the originals **and** the node key in `archive/<sealedId>/` for
7 days; restore is a move. At day 7 both are destroyed and only the cold copy remains.
**Cost.** For 7 days a sealed node is recoverable with the same factors as a live one. That is
the intended semantics of a recovery window, and it is stated in the seal dialog.

---

## Operator questions — DECIDED 2026-08-05

The seven open questions were referred to the operator, who asked for the recommended answer
in each case. They are now **decisions, not defaults**. Each is a rule; changing one needs a
superseding ADR.

## ADR-028 · ~~Migrate flat~~ · **VOID 2026-08-05 — there is no migration** (`11_MIGRATION.md`)

**Decision.** `acme`, `contoso`, `northwind` migrate as three depth-1 nodes. No sub-nodes are
created. **The dry-run report additionally emits a `suggested-splits` section** — name-prefix
clusters it observed (e.g. `ACME_TESTNET_*` vs `ACME_MAINNET_*`) — as information only.
**Rejected.** Splitting during migration. Two risky operations at once means a problem cannot
be attributed to either; and you cannot design a boundary well until you have watched how you
actually reach for the credentials behind it.
**Consequence.** Splitting later is one `node add` plus `entry.move`, both re-encrypting
cleanly. Splitting is cheap; an unattributable migration failure is not.

## ADR-029 · Entry names stay in the plaintext manifest — with a per-node opt-out *(was Q-2)*

**Decision.** Default `policy.privateNames: false` — entry names remain in the manifest, so
the graph and search work while locked. **A node may set `privateNames: true`**, and then its
manifest stores counts and opaque ids only; its entries are absent from locked search and
render as `••••` until unlock.
**Rejected.** Encrypting all names (kills the locked graph and locked search — the two things
that make locking cheap enough that people actually lock) and leaving no option at all (a node
holding `ledger-cold-seed` leaks real intent through its names alone).
**Consequence.** The wallet node turns it on (ADR-033); everything else stays fast.
Supersedes the "No for V2.0" half of AR-1.

## ADR-030 · Auto-lock: 15 minutes for the vault, 5 for critical nodes *(was Q-3)*

**Decision.** Vault idle auto-lock **15 min**, plus lock on sleep, screen lock and session end.
**Any node containing a `critical` entry additionally node-locks at 5 min** on its own timer
(the node-level lock from Pass 2 F-7).
**Rejected.** A single global timer. Fifteen minutes is right for the node you are working in
and far too long for the one holding seed phrases; one number cannot serve both.
**Consequence.** Ordinary work is uninterrupted; the dangerous node is shut most of the day.

## ADR-031 · Lite is the product default; Pro is the operator's install *(was Q-4)*

**Decision.** First run defaults to **Lite** and asks one question — *"Do you want maintenance
controls (verify, doctor, audit, grants)? You can change this any time."* Skipping it keeps
Lite. **This operator's own install runs Pro**, since `verify`/`doctor`/`audit` are part of
their routine.
**Rejected.** Pro as the default. A first-run screen that opens on ten settings sections
teaches a new user that this tool is complicated, and the recovery from that impression is
expensive.

## ADR-032 · Keep long credential names; show short ones *(was Q-5)*

**Decision.** Storage keeps `ACME_VPS_PASSWORD` verbatim. The short form is registered as
an alias. **Additionally, the UI displays the name with the node prefix stripped when it
matches the containing node** — inside the `acme` node the entry reads `VPS_PASSWORD`,
while `credmgr get ACME_VPS_PASSWORD` and `credmgr get VPS_PASSWORD` both work.
**Rejected.** Renaming at migration (breaks every consumer on the machine — shell helpers,
deploy scripts, three project agents, `wallets.env`) and doing nothing (leaves the vault
reading `ACME_…` inside a node already called *acme*, which is the redundancy the
node model exists to remove).
**Consequence.** Display and identity are decoupled, which is what makes the rename optional
forever rather than urgent.

## ADR-033 · Wallet-class nodes are hardened automatically, by proposal *(was Q-6)*

**Decision.** A node holding any entry with a `seed-phrase` or `private-key` field is
**proposed** for: `requireTwoFactor: 'always'` · `lockAfterSeconds: 300` ·
`privateNames: true` · `agentAccess: 'read-only'`. The proposal is a one-click banner naming
each consequence. It is never applied silently.
**Rejected.** Applying it automatically (a vault that changes its own security policy without
telling you is a vault you stop trusting) and leaving it entirely manual (the node that most
needs hardening is the one you set up once and never revisit).
**Consequence.** The highest-value target gets the strongest posture, on a decision the
operator made and can see in the audit log.

## ADR-034 · ~~V1 retired on evidence~~ · **VOID 2026-08-05 — V1 is not retired.** It ships and is supported alongside V2.

**Decision.** The 45-day window stands as a **minimum**, and archiving additionally requires
all four: (a) zero reads from V1 in the preceding 30 days, measured by the shim log;
(b) every consumer in `11 §6` updated and verified; (c) a **restore test** — a V2 backup
restored into a scratch location and a credential read out of it; (d) `credmgr verify` green
on V2. Any failure extends the window by 30 days rather than proceeding.
**Rejected.** Date-only retirement. Archiving a credential vault on a calendar is how you
discover a missing credential three months later, with the archive on an external volume and
no memory of what it held.
**Consequence.** The window can only ever grow, and it ends with proof rather than a
reminder firing.

---

---

## Added during Phase 0 build

## ADR-035 · `apps/desktop/src-tauri` is its own Cargo workspace, on current stable, not the 1.78 MSRV pin

**Context.** `16_CROSS_PLATFORM.md §7` and `12_BUILD_PLAN.md` Phase 0 call for one pinned
`rust-toolchain.toml` at MSRV 1.78 across the workspace. Scaffolding `apps/desktop` with
`create-tauri-app` (Tauri 2, Svelte 5, Vite, TS) and joining it to the `crates/` workspace
failed at `cargo build --workspace`: Tauri 2's dependency tree pulls `idna_adapter 1.2.2`
(transitively via `url`), whose manifest requires Cargo's `edition2024` feature — unstable
before Rust 1.85. The 1.78 toolchain cannot even parse that manifest, regardless of what
`crates/core` itself uses.
**Decision.** `apps/desktop/src-tauri` is excluded from `v2/Cargo.toml`'s workspace
(`exclude = [...]`) and carries its own `rust-toolchain.toml` pinned to the current verified
stable (`1.94.1`). The 1.78 MSRV pin applies only to `crates/core`, `keystore`, `brokerd`,
`cli`, `mcp` — the pieces that ship as standalone, long-lived signed binaries and CLI/MCP
surfaces, where reproducibility across years matters most. The desktop shell already tracks a
fast-moving GUI toolkit and gains nothing from an artificially old compiler.
**Rejected.** Forcing Tauri's dependency tree down to edition-2021-only versions (fights the
upstream ecosystem indefinitely, and Tauri 2 itself does not promise a 1.78 MSRV); dropping the
1.78 pin workspace-wide (defeats the reproducibility the pin exists for on the security-critical
crates).
**Consequence.** Two independent `Cargo.lock` files, two toolchains, verified working
independently: `cargo build --workspace --locked` (v2/, 1.78.0) and `cargo build` inside
`apps/desktop/src-tauri` (1.94.1). CI must run each with its own toolchain step — recorded in
`.github/workflows/build.yml`.

---

## ADR-036 · `crates/core`'s crypto and proptest dependencies pinned below latest, for the same MSRV reason as ADR-035

**Context.** Adding `chacha20poly1305`, `x25519-dalek`, `hkdf`, `sha2`, `secrecy`, `zeroize`
(`16_CROSS_PLATFORM.md §2`'s crate table) at their latest versions hit the identical wall ADR-035
found in Tauri's tree: `sha2 0.11`/`hkdf 0.13`/`chacha20poly1305 0.11` pull `block-buffer 0.12.1+`,
and `zeroize`'s "derive" feature (needed transitively by `x25519-dalek`'s "zeroize" feature) pulls
`zeroize_derive 1.5.0` — both require Cargo's `edition2024` feature, unavailable below Rust 1.85.
Unlike ADR-035, this collision is **inside** the 1.78-pinned `crates/` workspace itself, not a
separate Tauri tree — there is no "exclude it" escape hatch here.
**Decision.** Pin to the last MSRV-1.78-compatible generation of each: `chacha20poly1305 = "0.10"`,
`hkdf = "0.12"`, `sha2 = "0.10"`, `x25519-dalek = "2"`, `zeroize = "1.7"`, plus a direct
`zeroize_derive = "=1.4.2"` pin to force the transitive resolution (Cargo otherwise resolves it to
1.5.0 regardless of the `zeroize` pin, since it's a separate crate in the graph). Dev-dependencies
`proptest` and `tempfile` (proptest's own dependency, used for regression-file persistence) hit the
same wall at their latest versions and are pinned the same way (`proptest = "=1.4.0"`,
`tempfile = "=3.15.0"`).
**Consequence.** `16_CROSS_PLATFORM.md §2`'s crate table names the *crates*, not exact versions —
this ADR is the record of why the versions actually pinned in `Cargo.toml` are a generation behind
crates.io's latest, so a future session doesn't "helpfully" bump them straight into the same
edition2024 wall. Re-attempt the latest versions once the toolchain pin moves to 1.85+ (see
ADR-035's Tauri toolchain, `1.94.1`, as the eventual convergence target if the two pins are ever
unified).

---

## ADR-037 · Envelope AAD binds the caller's asserted context, not the envelope's own stored header field

**Context.** `04_CRYPTO_AND_KEYS.md §3` and `03_DATA_MODEL.md §7` state the AAD "covers magic ‖
version ‖ suite ‖ nodeId ‖ entryId" without specifying whether `nodeId` means the 16-byte header
field as stored in the envelope, or the value the caller (storage layer) asserts based on where it
found the file. These differ exactly in the attack P-3 exists to catch: relocating an envelope into
a different node's directory does not change the bytes stored inside it.
**Decision.** `nodeId` and `entryId` in the AAD are the caller's asserted values — supplied to both
`seal()` and `open()` as explicit parameters, sourced from the entry's storage path (`nodes/<id>/
entries/<entryId>.env`), never read back out of the envelope's own bytes for this purpose. The
16-byte header field is written from the same asserted value at seal time, and checked against it at
open time as a fast, clearly-named failure (`CryptoError::NodeIdMismatch`) *before* the AEAD
call — but the AEAD tag, not that check, is what actually enforces the binding; the header field is
informational (`03 §2`'s "which key do I need without decrypting"), not the security boundary.
**Also decided in the same pass:** the on-disk 16-byte `nodeId` field is zero-padded raw UTF-8 (every
real node id — `global`, `orphan`, `n_` + 8 hex — is ≤ 10 bytes), not a hash. A hash would make the
field genuinely opaque, contradicting "in cleartext" in `03 §7`'s framing.
**Rejected.** Deriving the AAD from the envelope's own stored header field: an attacker who moves the
file changes nothing about those bytes, so P-3 would not hold under that reading.
**Test:** `crates/core/src/envelope.rs::tests::relocated_envelope_fails` and
`tests/properties.rs::p3_wrong_asserted_node_id_fails` (1000 cases).

---

## ADR-038 · The bulk parser's value never strips whitespace beyond the mandatory single separator space

**Context.** `08_FIELD_MODEL.md §3.1`'s formal grammar reads `LABELLED_LINE ::= LABEL ":" " " WS*
VALUE_TEXT` — a mandatory space *then* `WS*` (zero or more additional whitespace) before the value
starts, which if implemented literally strips leading spaces from the value. `08 §3.5` states
plainly: *"No trimming of value whitespace beyond the trailing newline. A password may begin or end
with a space, and truncating it silently is the worst possible bug in this product."* These
contradict each other for e.g. `"password:  x"` (two spaces): the grammar produces `"x"`, the prose
guarantee requires `" x"`.
**Decision.** The prose wins. Exactly one literal space after the colon is the separator; everything
after it — including further leading whitespace — is the value, untouched. The formal grammar's
`WS*` is treated as imprecise shorthand for "there is a space here", not a second stripping rule.
**Why the prose, not the grammar:** the prose guarantee is stated as an explicit, load-bearing
product decision with a named failure mode ("the worst possible bug in this product"); the grammar
snippet is definitional scaffolding with no accompanying rationale, and grammars are exactly the
kind of artifact that accumulates small imprecisions a human reader mentally corrects for without
noticing. When one of two conflicting statements names the cost of getting it wrong and the other
doesn't, that asymmetry is itself evidence of which one was actually decided on purpose.
**Test:** `crates/core/src/parser.rs::tests::leading_and_trailing_spaces_in_value_survive`.

---

## ADR-039 · Phase 2's `vaultGeneration` counter is a store-owned trait, not a Phase-5 borrow

**Context.** `12_BUILD_PLAN.md` Phase 2 requires "the external `vaultGeneration` counter in the
Keychain (F-3)" and gate item I-20 (rolled-back registry refused on generation). But
`04_CRYPTO_AND_KEYS.md §6a` and `16_CROSS_PLATFORM.md §3` place that counter behind
`PlatformKeystore::read_counter`/`write_counter` — a trait whose real implementations
(Secure Enclave Keychain item, DPAPI, TPM NV index, XDG-state file) are explicitly Phase 5
work (`12_BUILD_PLAN.md` Phase 5, `16 §4`). Phase 2 cannot depend on Phase 5's crate without
breaking the plan's own sequencing rule ("Nothing from Phase 1 blocks \[Phase 2\]" — the
inverse is intended too: a later phase's concrete implementation must not become an earlier
phase's compile-time dependency).
**Decision.** `crates/store` defines its own minimal `GenerationCounter` trait —
`read(name) -> Result<u64>`, `write(name, value) -> Result<()>` — a strict subset of
`PlatformKeystore`'s two counter methods, with no dependency on `credmgr-keystore`. It ships
one concrete implementation now: `FileGenerationCounter`, a `0600` file holding the counter
value plus an `HMAC-SHA256(HKDF(RK, "generation-counter"), value)` tag, stored under the
paths `16 §5` already documents as Linux's own TPM-less fallback ("a `0600` file under
`$XDG_STATE_HOME/credmgr/` with an HMAC (weaker; the UI says so)"). This is not a Phase-2
shortcut invented to unblock a test — it is the design's own documented answer for the
weakest-real-platform case, generalised to serve every platform until Phase 5 lands the
stronger ones.
**Phase 5's job:** each `PlatformKeystore` implementation's `read_counter`/`write_counter`
becomes the counter backing the broker actually uses at runtime (macOS Keychain item, DPAPI
blob, TPM NV index); `FileGenerationCounter` remains the Linux no-TPM fallback per `16 §4.3`,
now already built rather than newly needed. No migration step is required — `crates/store`'s
`GenerationCounter` trait is the seam Phase 5 implements against, not a type Phase 5 must
delete.
**Also decided in the same pass — path resolution.** `16 §5`'s per-OS path table has no
listed crate to read it from (`16 §2`'s crate-selection table does not mention one). Rather
than add an unvetted `dirs`-family dependency and risk the same `edition2024` MSRV wall that
forced ADR-035/036/038's pins, `crates/store::paths` hand-resolves the three rows directly
from `HOME`/`APPDATA`/`XDG_DATA_HOME` et al. — about fifteen lines, no dependency, and it is
exactly the set of env vars those crates would have read internally anyway.
**Also decided — backup scheduling split.** Phase 2's brief also lists "automatic backup
scheduling (F-16)" and gate item "fires daily and before seal/destroy/re-key/migrate."
Firing on a *timer* needs a running process with a clock, which `crates/store` deliberately
does not have (no daemon, no loop) — that is `crates/brokerd`'s job, arriving in Phase 3.
Phase 2 ships the primitive the scheduler will call (`store::backup::create_backup`, tested
directly) and leaves the "daily, and before seal/destroy/re-key/migrate" *triggering* to
Phase 3, which is the first phase with a process able to trigger anything. The same split
applies to `04 §7`'s "the archive is itself encrypted, to a key derived from either the
recovery code or a separate backup passphrase": recovery codes aren't modeled before Phase 5
(`07_TWO_FACTOR.md`) and Argon2id isn't a dependency until then (`16 §2`'s crate table lists
`argon2` under Phase 5's work, not Phase 1/2's pinned crypto set), so there is no key to
encrypt the archive *to* yet. `create_backup` in Phase 2 produces the correctly-selected,
unencrypted bundle bytes — deciding *what* belongs in a backup is storage-layer work and
buildable now; encrypting the bundle is one more call Phase 5 wraps around this function's
output once a recovery-code/passphrase-derived key exists to encrypt it to.
**Rejected.** Blocking Phase 2 until Phase 5 exists (violates "one phase per session" and the
plan's own stated independence of Phase 4/5/6 from each other); vendoring a fake
`PlatformKeystore` stub in `crates/store` (couples a storage crate to a security-boundary
trait it has no business depending on, for a feature — hardware presence — storage doesn't
need).
**Test:** `crates/store/src/generation.rs` — round-trip, tamper-detection, and
lower-generation-refused cases; `crates/store/tests/rebuild_registry.rs::rolled_back_registry_is_refused_on_generation`.

---

## ADR-040 · On-disk timestamps are Unix epoch seconds (`i64`), not ISO-8601 strings

**Context.** `03_DATA_MODEL.md`'s TypeScript sketches type every timestamp field (`Node.created`,
`Grant.createdAt`/`expiresAt`/`lastUsedAt`, `Entry.created`/`modified`/`rotatedAt`/`expiresAt`,
manifest entry `modified`) as `string` — implicitly ISO-8601, the conventional reading of a
TS `string` timestamp. `crates/core::registry::Grant.expires_at` was already `Option<i64>` as
of Phase 1 (chosen so `resolve()` compares expiry against an explicit `now: i64` parameter
without parsing a date string in a crate that must stay pure and dependency-light). Phase 2
now has to pick one convention for every other timestamp `crates/store` writes, and picking
ISO-8601 there while `expires_at` stays `i64` would mean the same file mixes two timestamp
representations for no reason a reader could infer.
**Decision.** Every timestamp `crates/store` writes — `Node.created`, `Grant.createdAt`/
`lastUsedAt`, manifest entry `modified`, archive/audit record timestamps — is Unix epoch
seconds, `i64`, matching `expires_at`'s existing convention. This is an internal wire format:
nothing outside this codebase reads `registry.json`/`manifest.json` directly (`credmgr export`
produces a documented, separate format per `04 §7` and is unaffected), and every in-repo
consumer (CLI Phase 4, UI Phase 6, MCP) goes through `crates/core`/`crates/store`'s typed
structs, never hand-parses the file.
**Rejected.** A hand-rolled ISO-8601 formatter/parser in `crates/store` (real bug surface —
leap years, leap seconds, timezone-offset edge cases — for a format with no external reader to
satisfy); pulling in `chrono` or `time` (both crates evaluated: current majors of either pull a
dependency generation that risks the same `edition2024` MSRV wall as ADR-035/036/038, and even
if they didn't, a dependency exists here to serve exactly one need — string formatting — that
epoch integers make unnecessary); converting `expires_at` to a string instead and taking the
inconsistency the other direction (bigger diff into already-tested Phase 1 code for a cosmetic
gain, and epoch integers are what `resolve()`'s pure-compute contract actually wants).
**Consequence.** If a future phase needs to *display* a timestamp (the UI, Phase 6, certainly
will), that phase converts at the presentation boundary — a one-line `i64 → Date` — not here.
**Test:** every `crates/store` type carrying a timestamp round-trips through `serde_json` as a
JSON number in its own unit tests (`registry_file.rs`, `manifest.rs`, `audit.rs`).

---

## ADR-041 · Phase 3 builds `PlatformKeystore` + the `Software` tier only; hardware tiers stay Phase 5

**Context.** `12_BUILD_PLAN.md` Phase 3 requires `credmgrd` to have real `lock`/`unlock`
semantics and a hot key set — both meaningless without something that can wrap and unwrap the
root key. `16_CROSS_PLATFORM.md §3` places that behind `PlatformKeystore`, and the plan
assigns **all four implementations** to Phase 5, with an explicit gate: *"Do this phase on all
three OSes, or do not claim it… a platform that cannot pass \[conformance\] ships as
`Tier::Software` and says so."* Taken literally this reads as "no keystore code before Phase
5," which would leave Phase 3 unable to build or test unlock at all — the same shape of gap
ADR-039 found in Phase 2 for the generation counter.
**Decision.** `crates/keystore` ships the `PlatformKeystore` trait, `Capabilities`/`Tier`
types (`16 §3`, verbatim), and **one** concrete implementation: `SoftwareKeystore`, Argon2id
over an operator passphrase (`16 §4.4`). This is not a Phase-3 shortcut invented to unblock a
test — `16 §4.4` already documents `Software` as *"Always present on every platform, as the
escrow wrap"*, i.e. it is not one of the three hardware tiers being pulled forward, it is the
one tier the design already requires unconditionally. `verify_presence` on this
implementation re-prompts for the passphrase (the only "presence" a software-only tier can
offer, and `16 §3`'s own doc comment allows this: `user_presence` is a `Capabilities` field,
not a hard requirement of the trait); `Capabilities::user_presence` is `false`, so R0's
orphan-reveal path and any UI copy correctly reports "passphrase only," never overstating
protection, consistent with `16 §3`'s own instruction to state the tier in plain words.
Counter storage reuses the `read_counter`/`write_counter` shape already proven by
`credmgr-store`'s `FileGenerationCounter` (ADR-039) — same file-plus-HMAC construction, same
outside-the-vault-directory location, now behind the trait instead of store's narrower
`GenerationCounter` seam. `crates/store` keeps its own `GenerationCounter` trait unchanged
(no new coupling introduced); `crates/brokerd` is the first crate to depend on
`credmgr-keystore` for a real unlock, exactly as Phase 3 intends.
**Phase 5's job, unchanged in shape:** macOS Secure Enclave, Windows Hello/TPM+DPAPI, and
Linux TPM2/secret-service implementations land behind the same trait, each with real
`user_presence: true` behaviour and the keystore conformance suite (`13_TEST_PLAN.md §1`) run
against all four on the CI matrix. `SoftwareKeystore` does not get deleted or replaced — per
`16 §4.4` it remains the permanent escrow wrap on every platform, and becomes the Linux
no-hardware fallback in addition.
**Rejected.** Blocking Phase 3 until Phase 5 exists (repeats the exact mistake ADR-039 already
named and rejected — "violates 'one phase per session' and the plan's own stated independence
of Phase 4/5/6 from each other"); a broker-internal fake keystore that never touches
`crates/keystore` (couples `brokerd` to a shape Phase 5 would then have to migrate away from,
the inverse of the seam ADR-039 built); shipping `SoftwareKeystore` claiming
`hardware_backed: true` to make Phase 3's tests resemble Phase 5's more closely (exactly the
"lock icon that means less than the user thinks" `02 §6` and `16 §3` both explicitly reject).
**Test:** `crates/keystore/src/software.rs` — wrap/unwrap round trip, wrong passphrase fails
authentication, counter persists across a fresh `SoftwareKeystore` instance over the same
state dir, `Capabilities` reports `Tier::Software` / `hardware_backed: false` /
`user_presence: false`.

---

## ADR-042 · Approval-on-demand's decision gate is `Capability::Admin` on Phase 3; the
value returns by retry, not a blocking push

**Context.** `12_BUILD_PLAN.md` Phase 3's exit gate requires "Approval-on-demand: locked-vault
reveal → notification → one approval → one value, and the vault is still locked afterwards" —
listed as Phase 3 scope, not deferred. `07_TWO_FACTOR.md §5a` (F-15) and `06_ACCESS_GRAPH.md`'s
R1 row both specify that a `reveal` against a *locked* target returns `approval_pending`, not a
flat denial — before this ADR, `ops::dispatch`'s `entry.reveal` arm did not do this: R1 always
produced `node_access_denied{rule:"R1"}` (I-14's own test asserted exactly that), and the
`OpError::ApprovalPending` wire type existed but was never constructed anywhere. The full F-15
flow as drawn — an OS notification from the native app, Touch ID on Approve — genuinely needs
`notify_approval`, a Tauri IPC command (`18_ENDPOINT_INDEX.md §4`), and live presence
attestation, neither of which exist before Phase 5's native shell (the same gap `ops.rs`'s own
module doc already names for `node.reparent`). Taken literally, F-15 looks blocked on Phase 5
exactly like reparent's positive path is — but unlike reparent, the *value return* has no actual
presence dependency: `state.reauth_root_key()` already unwraps the root key regardless of lock
state (used today by `node.seal`/`node.restore`/anomaly-audit), and from the root key, a node's
wrapped private key unwraps the same way `unlock()` does for every node — neither step touches
the hot key set. So while F-15's *notification/decision UI* is Phase 5/6 territory, its
*value-return mechanism* is genuinely buildable now.
**Decision.** Split F-15 the same way ADR-041 split the keystore trait from its hardware
implementations: build the whole broker-side mechanism for real, substitute the one piece that
generically needs a human with the factor Phase 3 actually has.
- `entry.reveal` on an R1-locked target checks whether the request would be `Allow` under every
  *other* rule (re-running `resolve()` with lock state ignored, the same "re-scan to enrich, never
  to change the decision" pattern `find_expired_grant_note` already uses) — if so, it creates or
  reuses a `PendingApproval` (120 s TTL, one per `(node, entry)` in flight at a time) and returns
  `approval_pending`; if the target was never reachable regardless of lock state, it returns the
  ordinary `node_access_denied` — locking a vault must not turn an unreachable node into a
  notification-worthy event.
- A new op, `vault.approval_decide {request, approved}`, gated on `Capability::Admin` — the same
  substitution `vault.node_lock`/`node.seal`/`node.restore` already make for "the human factor,
  adapted to what Phase 3's transports can actually assert." Phase 5's native app calls this same
  op after a real Touch ID tap; nothing about the op's shape changes when that lands, only what
  gates reaching it.
- The value returns by **retry**, not a blocking connection or a pushed event: the original
  caller re-issues the identical `entry.reveal` once decided. `07 §5a` already documents this
  shape — "`credmgr_get`'s tool description tells agents to fetch what they need early and to
  expect a possible short wait, so this is a designed interaction rather than a surprise
  timeout" — a designed retry, not new behaviour invented for this ADR. An approved, unexpired,
  unconsumed request is decrypted with `reauth_root_key()` + `unwrap_node_key()` and consumed
  (removed) on first successful retry — "one entry, one field, once" (`07 §5a`) — never added to
  `hot_keys`, so `is_locked()` stays `true` throughout. A denied or expired request returns
  `approval_denied`; expiry is default-deny, enforced lazily wherever a request is next read
  (queried by `entry.reveal`'s retry, or decided by `vault.approval_decide`) rather than needing
  a live timer thread, since nothing observes a `PendingApproval` between its creation and the
  next read of it.
**Rejected.** Leaving `entry.reveal` returning a flat R1 denial until Phase 5 (repeats the
"block Phase 3 until Phase 5 exists" mistake ADR-039 and ADR-041 both already rejected, and
directly contradicts the Phase 3 exit gate's own wording, which is unambiguous that this item
is in scope now); gating `vault.approval_decide` on `Origin::Native` the way `node.reparent`
gates its positive path (unlike reparent, F-15 does not actually need presence for the *value*
to return safely — the vault stays locked either way — so refusing it unconditionally would be
over-cautious relative to what the mechanism actually requires, not a faithful reading of the
gap); a blocking/long-poll connection that holds the original request open until decided (adds
connection-lifetime state the newline-delimited request/response transport was not built for,
and contradicts `07 §5a`'s own documented retry-based interaction).
**Consequence.** The full round trip — locked reveal → `approval_pending` → `Capability::Admin`
decide → retried reveal → value, vault still locked — is real and tested today. When Phase 5's
native shell exists, `notify_approval` renders the notification and a real presence check can be
threaded into what calls `vault.approval_decide`; no change to `entry.reveal`, the `PendingApproval`
bookkeeping, or the decrypt path is needed for that to happen.
**Test:** `crates/brokerd/tests/phase3_exit_gate.rs` — locked reveal on an otherwise-reachable
entry returns `approval_pending`; locked reveal on an unreachable entry still returns the
ordinary `node_access_denied` (no notification for a request that was never going anywhere);
`Capability::Admin` decide + retry returns the value with `is_locked()` still `true`; a denied
decision refuses the retry; an expired, undecided request defaults to denied; a consumed
approval cannot be replayed by a second retry.

---

**Amended (ADR-079, 4a).** The value is no longer decrypted at the retry: it is decrypted and staged when
the decision is made, and the retry only hands it over — so the retry never derives a key, a lock drops
every staged value, and a reveal or a decision on a wholly locked live vault answers `vault_locked`. The
paragraph above that has the retry decrypt with `reauth_root_key()` is the original design, which a
locked durable vault refuses by design.

## ADR-043 · Auto-lock: idle-timeout is real Phase 3 logic; sleep/screen-lock/session-end are a
native signal Phase 5 will call, not something Phase 3 can detect itself

**Context.** `12_BUILD_PLAN.md` Phase 3's exit gate requires "Auto-lock fires on idle, sleep and
screen lock" (ADR-030: 15-min vault idle, 5-min per-node for any node holding a `critical`
entry, plus lock on sleep/screen lock/session end). Detecting sleep, screen lock or session end
needs OS-level notifications — macOS `NSWorkspace` sleep/lock notifications, Windows
`WM_POWERBROADCAST`/session-change messages, Linux logind `PrepareForSleep`/`Lock` D-Bus
signals — that only exist behind a running native app, i.e. Phase 5's Tauri shell
(`12_BUILD_PLAN.md` Phase 5: "the native shell"). `credmgrd` itself is a headless UDS daemon
with no window, no OS event loop hook, and (by design, `PRIVACY.md`) no framework that could
receive those notifications on its own. Idle-timeout has no such dependency: it only needs to
know when the broker last did something, which the broker already knows from its own request
traffic.
**Decision.** Split the same way ADR-042 splits F-15: build the part that has no native
dependency for real, and give the native-dependent part a single, generic, already-tested entry
point rather than leaving it unbuilt.
- `BrokerState` tracks `last_activity` (vault-wide) and `node_last_activity` (per node),
  touched by every request `handle_request` processes for that request's scope's node
  (`state.touch_activity`). `tick_autolock(now)` compares `now` against `last_activity` and the
  configured vault-idle threshold (default 900 s, ADR-030), and separately against each node
  whose `NodePolicy::lock_after_seconds` is `Some` (already a real, persisted field —
  `06_ACCESS_GRAPH.md`: "Set from the node context menu (`Lock now`) or by policy
  `lockAfterSeconds`, which auto-locks") — locking the vault or the individual node exactly as
  `vault.lock`/`vault.node_lock` already do. A caller (a background thread in `server::run`,
  once Phase 4 wires a real vault directory to run against — `main.rs`'s own doc comment
  explains why that wiring isn't here yet) ticks it periodically; the tick logic itself needs no
  such wiring to be tested, since it takes `now` as a parameter like every other pure-ish check
  in this crate.
- `BrokerState::external_lock_signal(reason)` is the one entry point sleep, screen-lock and
  session-end all reduce to: an unconditional `self.lock()`. Phase 5's native shell subscribes to
  the three OS notifications and calls this same function for all of them — there is exactly one
  thing to test on the Phase 3 side (calling it locks the vault), and exactly one thing left for
  Phase 5 to add (the three OS subscriptions that call it), not three separate mechanisms.
**Rejected.** Leaving auto-lock entirely unbuilt until Phase 5 (the idle-timeout half has no
native dependency at all — repeats ADR-039/041/042's already-rejected "block Phase 3 on Phase 5"
pattern for the one piece that does not need blocking); faking OS sleep/lock detection with a
polling heuristic (e.g. "the clock jumped" as a sleep proxy) in `credmgrd` itself (unreliable,
platform-fragile, and duplicates work Phase 5's native shell must do properly with real OS APIs
regardless, per `16_CROSS_PLATFORM.md`); a single combined vault-wide-only timer with no
per-node timer (ADR-030 explicitly rejected this: "one number cannot serve both" ordinary work
and a seed-phrase node).
**Consequence.** Idle-based auto-lock (both vault-wide and per-critical-node) is real and tested
today, using the exact thresholds ADR-030 already decided. Sleep/screen-lock/session-end auto-lock
is one function call away from complete the moment Phase 5's native shell exists to make it —
nothing about `external_lock_signal`, `tick_autolock`, or the threshold config needs to change
for that wiring to land.
**Test:** `crates/brokerd/tests/phase3_exit_gate.rs` — idle past the vault threshold locks on
tick; idle past a node's own `lockAfterSeconds` locks only that node, not the vault; activity
resets the idle clock; `external_lock_signal` locks immediately regardless of any timer state.

---

## ADR-044 · Auth-failure backoff is a second, uid-keyed limiter — distinct from the
existing cross-node-denial `RateLimiter`

**Context.** `12_BUILD_PLAN.md` Phase 3's exit gate requires "Rate limiter backs off as
specified and shares its counter across auth paths." `crates/brokerd/src/rate_limit.rs`
already exists and is tested, but its own module doc ties it explicitly to
`05_THREAT_MODEL.md §7`: "≥5 cross-node denials in 10 minutes raises an anomaly" — a flat
threshold counter for detection, with no backoff/lockout behaviour at all. The exponential
schedule the exit gate's wording actually describes — "5 failures → 30s lock, doubling
(30s → 1m → 2m → 4m → 8m), capped at 15 min. Per scope. Shared counter with the passphrase
path so an attacker cannot alternate" — is `07_TWO_FACTOR.md §5`'s row for *authentication*
failures (passphrase/TOTP), a different threat (credential guessing) from `05 §7`'s cross-node
probing, and was never built: nothing in `rate_limit.rs` locks anyone out of anything, it only
counts. Phase 3 has exactly one authentication path, `vault.unlock`'s keystore passphrase
(TOTP is Phase 5) — but "shared counter with the passphrase path" only makes sense as a
constraint if the counter is built to outlive that being the only path.
**Decision.** A second limiter, `crates/brokerd/src/auth_backoff.rs`'s `AuthBackoff`, separate
from `RateLimiter` because the two answer different questions (detection-threshold vs.
lockout-duration) off different inputs (denials vs. auth failures) — folding them into one type
would make either the anomaly threshold or the backoff schedule secondary to the other for no
reason. Keyed by uid, exactly like `RateLimiter` already is, which is what makes "shared counter
with the passphrase path" true by construction rather than by a special case: Phase 5's TOTP
failures feed the same `record_failure(uid, now)` call this ADR wires `vault.unlock` to, so an
attacker cannot exhaust one factor's lockout budget then switch factors as if starting fresh.
Wired into `server::handle_request`, the same layer (not `ops::dispatch`, which has no uid) the
existing `RateLimiter` is wired into: before dispatching a `vault.unlock` request, check
`remaining_lockout(uid, now)` and refuse with `OpError::RateLimited` (no attempt against the
keystore at all — an unnecessary Argon2id hash is exactly the CPU cost a lockout should avoid)
if still within backoff; after dispatch, `record_failure` on `WrongPassphrase` or
`record_success` (clearing the counter — the schedule is about *consecutive* failures) on `Ok`.
**Rejected.** Extending `RateLimiter` with a second mode (conflates two independent thresholds
behind one type's tests, and the module doc's own `05 §7` citation would stop matching what the
type does); keying by scope/node instead of uid (the spec's own wording, "an attacker cannot
alternate," is about the same *caller* trying different targets, not different targets being
independently rate-limited — uid keying is what already denies that alternation for
`RateLimiter`, for the identical reason); enforcing the lockout inside `ops::dispatch` (would
require plumbing a uid into every call site's signature — `resolve()`'s access rules and this
purely-operational backoff are different concerns Phase 3 has kept apart everywhere else, e.g.
the existing `RateLimiter` is server-layer-only too).
**Consequence.** `vault.unlock` now genuinely locks out a guessing attacker with the documented
schedule, sharing its counter with whatever Phase 5 wires TOTP into — no change to
`AuthBackoff`'s shape needed for that, only a second `record_failure`/`record_success` call site.
**Test:** `crates/brokerd/src/auth_backoff.rs` unit tests — no lockout before the 5th failure;
exact 30s → 1m → 2m → 4m → 8m → 15min-capped schedule; a success clears the counter; lockouts are
per-uid. `crates/brokerd/tests/phase3_exit_gate.rs` — `vault.unlock` through
`server::handle_request` is refused with `rate_limited` once locked out, without ever touching
the keystore; a correct passphrase after the lockout window elapses still succeeds.

---

## ADR-045 · The recovery-code root wrap is pure `crates/core` compute, built in Phase 4,
not deferred to Phase 5

**Context.** `12_BUILD_PLAN.md` Phase 4's exit gate requires
`scripts/emergency-decrypt.mjs` to "recover a value with only the recovery code, and is
tested." ADR-039 had, in passing, grouped the recovery-code wrap with Argon2id and called
both "not modeled before Phase 5" — reasoning that `argon2` "isn't a dependency until
[Phase 5]'s crate table lists it." Both halves of that premise are now stale: `argon2`
landed in Phase 3 already (`crates/keystore/src/software.rs`, for the software-tier
passphrase wrap — unrelated to this ADR), and more to the point, **the recovery-code wrap
never needed Argon2id at all.** `04_CRYPTO_AND_KEYS.md §2`'s own hierarchy diagram draws no
stretching function between the recovery code and the root key — only the passphrase arrow
passes through `scrypt`/Argon2id. That is correct: Argon2id exists to turn a *low-entropy*
secret (something a human can remember) into a key strong enough to resist offline guessing.
A 256-bit CSPRNG-generated recovery code has no such weakness to compensate for; deriving a
key from it is exactly the one-shot `HKDF-SHA512(ikm, info=label)` this crate already uses
for `keys::wrap_node_key` (wrapping a node's private key under the already-unwrapped root
key — also already-high-entropy `ikm`, also no stretching, also no platform dependency).
Read this way, the recovery-code wrap was never a Phase-5 hardware/keystore concern; it was
misfiled alongside the passphrase wrap in ADR-039 because both are described in the same
sentence of `04 §7`, not because they share a mechanism.

**Decision.** Add `crates/core/src/recovery.rs`: `generate_recovery_code` (32 CSPRNG bytes),
`format_recovery_code`/`parse_recovery_code` (upper-case hex, hyphen-grouped in 4s for
transcription — hex chosen over a word list or base32 specifically because the decoder on
the other end may be a dependency-free ~150-line Node script years from now with no shared
alphabet table to drift; `u8::from_str_radix` and a four-line JS loop cannot disagree about
what a hex digit means), and `wrap_root_with_recovery_code`/`unwrap_root_with_recovery_code`
(`HKDF-SHA512(ikm=code, info="credmgr/v2/root-wrap-recovery")` → ChaCha20-Poly1305, empty
AAD, matching `wrap_node_key`'s convention for a wrap keyed by material with nothing to bind
against). `RootRecoveryWrap`/`keys::WrappedNodeKey` both gain `to_bytes`/`from_bytes` —
`nonce (12) ‖ ciphertext‖tag`, no length prefix — defining, for the first time, the actual
on-disk format `paths::root_wrap_recovery()`/`node_key()` will hold, since no prior session
had written real bytes to either path (only placeholder strings in store's own fixture
tests). This is what lets `scripts/emergency-decrypt.mjs` exist and be tested this phase
rather than deferred again: unwrap RK from the recovery-code wrap, unwrap the target node's
key from `keys/nodes/<id>.key` using the same domain-separated HKDF label
`keys::wrap_node_key` already defines, then open the entry envelope exactly per
`envelope.rs`'s CMV2 format — three pure-compute steps, zero of which touch a keystore trait.

**Rejected.** Leaving the recovery wrap for Phase 5 alongside the hardware keystores (the
exit-gate line quoted above is Phase 4's, not Phase 5's — deferring it a second time, after
Phase 3 already deferred I-10/I-13, would make deferral a habit rather than a genuine
blocker); stretching the recovery code through Argon2id anyway "for consistency" with the
passphrase wrap (adds ~1s and a memory-hard dependency to a value that is already at the
security ceiling an AEAD key can use — stretching high-entropy input doesn't make it
stronger, it only makes recovery slower for no benefit); a word-list or base32 encoding
(more pleasant to transcribe by hand, but a wrong reading of this ADR's own risk: the
failure mode is a *disaster*, potentially on unfamiliar hardware with only whatever
`node:crypto`-adjacent primitives are at hand — hex minimizes the surface for the decoder
itself to be wrong, which matters more here than typing convenience).

**Consequence.** `scripts/emergency-decrypt.mjs` recovers a real value from a real on-disk
fixture using only the recovery code, and both root and node key wraps now have a defined
byte format that Phase 5's real vault-bootstrap flow (`credmgr init` equivalent, wherever it
ends up living) must write to, not invent.

**Test:** `crates/core/src/recovery.rs` unit tests — wrap/unwrap round trip, wrong code
fails, tampered wrap fails, wrapping is nondeterministic, bytes round trip, truncated bytes
rejected, format/parse round trip (including lower-case and separator-free input), and
rejection of wrong-length or non-hex input. `crates/core/src/keys.rs` — `WrappedNodeKey`
bytes round trip and truncation rejection, added alongside the existing wrap/unwrap tests.
`crates/cli/tests/emergency_decrypt.rs` — builds a real fixture vault with the actual Rust
crypto, then shells out to `node scripts/emergency-decrypt.mjs` and asserts the recovered
plaintext matches, proving Rust-written and JS-read formats actually agree rather than just
type-checking against each other.

---

## ADR-046 · Phase 5 builds gate 2FA and the MCP registry for real; the three hardware
`PlatformKeystore` tiers and the Tauri native shell stay deferred, honestly

**Context.** `12_BUILD_PLAN.md` Phase 5's exit gate bundles two very differently-shaped
pieces of work under one heading: "2FA and the native shell." Gate 2FA (`07 §3-5`) is pure
protocol logic — TOTP generation/verification against an explicit time parameter, a replay
ledger, a recovery-code set, a state machine sitting between "passphrase correct" and "node
keys loaded" — with **no hardware or interactive dependency at all**, the same shape ADR-041
already found for `SoftwareKeystore`. The other piece — macOS Secure Enclave, Windows Hello/
TPM+DPAPI, Linux TPM2/secret-service, and Tauri's presence/concealed-clipboard commands — is
the opposite: `16_CROSS_PLATFORM.md §7`'s own CI matrix is `{macos-14, windows-latest,
ubuntu-22.04}`, and the build plan's own words are unambiguous about what "done" requires:
*"Do this phase on all three OSes, or do not claim it… A keystore that compiles for Windows
but has never unlocked a vault on Windows is not implemented."* This session runs
non-interactively on one macOS development machine. It has no Windows or Linux host to build
or test against at all — two of the three tiers are unwritable-and-unverifiable by
construction here, not merely inconvenient. And macOS's own Secure Enclave tier needs a live
human's fingerprint on a live sensor at the moment `unwrap_root` runs (`04 §2`:
`kSecAttrTokenIDSecureEnclave` + `biometryCurrentSet`) — something a non-interactive session
cannot supply even on the one platform it does have, any more than it could type a passphrase
into an interactive prompt. Writing the macOS FFI code without ever exercising a real
Touch ID prompt would produce exactly the artifact the build plan's own sentence warns
against, just for macOS instead of Windows.

**Decision.** Split the same way every prior Phase-3/4/5 ADR in this file has split a phase
against a missing dependency: build the part with no such dependency for real, and record
precisely what's left rather than stub it or block on it.

- **Built this session, for real, with tests that do not mock the boundary:** vault-wide gate
  2FA (`crates/brokerd`'s `gate`/`gate_replay`/`pending_gate_unlock`/`elevations` state,
  wired into `vault.unlock`'s five-step sequence exactly as `07 §3` specifies) — all 8 tests
  from `07 §8` pass against the real dispatch path, not a stand-in. TOTP items' seed/code
  split (`totp.code`/`totp.seed`, `07 §6`) — `totp.seed` is capability-checked then
  unconditionally `PresenceRequired`, the identical "`Capability::Admin` substitutes, then
  presence blocks" shape `node.reparent`'s positive path already established in Phase 3, for
  the identical reason: no Phase 3/4/5-so-far transport can ever supply real presence. The MCP
  crate's tool registry and stdio JSON-RPC loop (`credmgr-mcp`) — I-13 (deferred by
  `isolation.rs`'s own module doc pending exactly this crate's existence) now runs for real
  against a live registry, and `crates/cli/tests/mcp_integration.rs` proves the whole stdio →
  socket → broker → response path end-to-end by spawning the real compiled binary, the same
  standard `broker_integration.rs` already set for the human CLI surface.
- **Deferred, unchanged in shape from ADR-041's own forward pointer:** the three hardware
  `PlatformKeystore` implementations and the keystore conformance suite running them on the
  CI matrix (`13_TEST_PLAN.md §1`, AR-9), plus Tauri's presence and concealed-clipboard
  commands (`apps/desktop/src-tauri` remains the Phase-0 skeleton — `lib.rs`/`main.rs` only,
  confirmed before writing this ADR). `SoftwareKeystore` is not a placeholder for these: per
  `16 §4.4` it is the permanent, always-present escrow tier on every platform, so the vault
  built so far is fully real and fully functional — every gate-2FA test in this session runs
  against it — just without hardware-backed root-key protection yet, which is the honest
  `Tier::Software` case the UI is already required to state in plain words (`16 §3`).

**What closing this properly needs, named so the next session opens with it instead of
re-deriving it:** (1) a Windows and a Linux host or CI runner — this cannot be worked around
from a single macOS machine; (2) for the macOS Secure Enclave tier specifically, either an
**interactive** session where a human is present to complete real `LocalAuthentication`
prompts, or a deliberately-designed test seam (a mockable presence layer behind the
`PlatformKeystore` trait, built and justified as its own decision — not assumed here) that
still exercises the real Security-framework FFI for everything except the biometric prompt
itself. Inventing that seam under time pressure inside an unrelated ADR would be exactly the
kind of unscoped addition the build's own discipline exists to prevent; it is named as future
work, not designed here.

**Rejected.** Fake/mocked hardware implementations that report `Tier::Hardware` or
`hardware_backed: true` without ever calling a real platform API (the precise "lock icon that
means less than the user thinks" `16 §3`/`02 §6` both already forbid, and ADR-041 already
rejected once for `SoftwareKeystore` specifically — this is that same rejection applied to
the harder case). Blocking Phase 5 entirely on Windows/Linux hosts or an interactive macOS
session existing (repeats the "block this phase until infrastructure exists" mistake
ADR-039/041/042/043 each already named and rejected, and contradicts `12_BUILD_PLAN.md`'s own
sequencing note that Phases 4/5/6 are independent and may interleave — gate 2FA and the MCP
registry are exactly the interleaved, independent slice this session could actually finish).
Writing the macOS Secure Enclave FFI code anyway, untested, on the theory that "it should
work" (the build plan's own sentence — "has never unlocked a vault… is not implemented" —
was written to foreclose exactly this move).

**Consequence.** Phase 5's exit gate is **partially** closed, and must be reported that way,
not rounded up: the two 2FA-adjacent bullets ("all eight tests in `07 §8` pass", the MCP/tool
surface implied by "Orphan reveal … is impossible from CLI and MCP") are real and evidenced;
"keystore conformance suite green on macOS, Windows and Linux," "presence unlock works on
each platform's real mechanism," and "the Security panel reports the correct tier per
platform" are not yet started in code, and any BUILD_LOG entry for this session must say so
in those words rather than "Phase 5 done."

**Test:** no new test obligation from this ADR itself (a scoping decision, not an
implementation) — the tests that *do* exist for what this ADR says is built are
`crates/brokerd/tests/phase5_gate.rs` (9), `crates/brokerd/tests/phase5_totp_items.rs` (7),
`crates/mcp/tests/i13_tool_registry.rs` (4), `crates/mcp/src/{tools,server}.rs`'s own unit
tests (9 + 4), and `crates/cli/tests/mcp_integration.rs` (4, real subprocess + real broker).

---

## ADR-047 · `graph.snapshot` is built and correct for today's access model; "the native app
sees its whole vault" needs a session/login mechanism that does not exist yet, named precisely

**Context.** Phase 6 (UI) opens on `design/graph-engine/VAULT_GRAPH_SPEC.md §2`'s contract:
"The canvas is fed one object... [and] must render correctly while the vault is fully
locked." Building the broker-side half of that (a new op, `graph.snapshot`, gated on
`Capability::List` exactly like `node.list`/`whoami` already are) surfaced a real question:
what scope does the *native app itself*, showing its owner their own whole vault, actually
run under? The obvious first attempt — a scope with `node_id: GLOBAL_ID` and
`Capability::Admin` — was tried in this session's own test fixture and **failed**, for a
structural reason, not a bug: `06_ACCESS_GRAPH.md §1`'s rules (R2 self, R3 "Global is
readable by every node", R4 strict upward inheritance, R5 opt-in descendant read, R6
depth-2-sibling sharing, R7 explicit grants) never grant a node read access to its own
*descendants* — not even Global's. "Everything reads Global" is direction-specific: every
node can read Global, Global cannot read everyone. There is, by design, no scope shaped
"one node_id" that legitimately sees an entire multi-project tree — that would contradict
"parents do not read children by default" applied to the one node that is everyone's parent.

**Confirmed by tracing where `Origin` actually comes from.** `crates/brokerd/src/scope.rs`'s
`resolve_scope` (`06 §4`'s resolution order) has exactly one path that can ever produce
`Origin::Native` or `Origin::HumanUi`: an **explicit token** (case 1, `presented_token`
looked up in `TokenStore`). Both cwd-based fallback paths — case 2 (workdir match) and case
3 ("cwd unknown... global, list only") — hardcode `Origin::Agent`, unconditionally, even for
case 3's literal "a stranger sees that the vault exists and nothing else." **There is
currently no code path, on any real transport, that ever constructs a token carrying
`Origin::Native` or `Origin::HumanUi`** — every test fixture in this codebase that uses one
(`admin_scope()` helpers throughout `crates/brokerd/tests/`) builds a `BrokerScope` by hand,
bypassing `resolve_scope` entirely. This is the same gap Session 8's BUILD_LOG traps named
for `Capability::Admin` ("the only way any client gets an Admin-carrying token today is
`TokenStore::issue`, called directly against `BrokerState` in a test fixture... Real
session/login is Phase 5 territory") — this ADR traces it one level deeper and names the
exact function and the exact two cases.

**Why per-node filtering is nonetheless the right behaviour for `graph.snapshot` as built,
not a workaround.** `03_DATA_MODEL.md §2` is explicit that `registry.json` is unencrypted
specifically so "the graph must draw, with correct topology and correct counts, while the
vault is locked" — and that this is a bounded, accepted leak *to whoever can read the file*,
i.e. the same OS user the broker itself runs as. That fact does not, by itself, justify
`graph.snapshot` bypassing `resolve_capability` for *whichever scope asks* — a cwd-scoped
agent sitting in `~/projects/acme/` must never receive `northwind`'s topology over this op
just because the file on disk is technically readable by the same OS user; `10_API_AND_MCP.md
§3.2`'s "No listing of nodes outside scope... nothing else enumerates the vault's topology"
exists precisely to keep that leak from being handed out over the wire to an agent. So the
same visibility filter `node.list`/`whoami` already use is correct here too, for every scope
that resolves the way scopes resolve today.

**Decision.** Ship `graph.snapshot` exactly as built: gated on `Capability::List`, filtered
through the identical `resolve_capability` per-node check `node.list`/`whoami` already use,
tested in `crates/brokerd/tests/graph_snapshot.rs` (6 tests: correct counts and structural
links while locked, sibling/child isolation, `gate.twofa`'s policy-vs-vault-gate-state
mapping, node-level-lock independence, capability refusal). Do **not** invent a bypass —
neither an `Origin::Native`-only carve-out with no real way to reach `Origin::Native` behind
it, nor a "trust `Capability::Admin` alone" shortcut that would let any test-constructed
scope claim it. Name the real blocker instead: **the native app cannot show its owner their
whole vault graph until some mechanism issues it a token whose reachability set is "the whole
tree," established at real unlock time** — the same missing piece Session 8 already flagged
for `node.seal`/`node.restore`'s Admin path, now traced to its root (`resolve_scope` never
produces a non-`Agent` origin outside a token). Designing that mechanism (most plausibly: real
`vault.unlock` issuing a `TokenStore` entry scoped as the vault owner, distinguished from an
ordinary agent token by something stronger than "asked nicely for `Capability::Admin`" — a
concrete design question this ADR deliberately does not answer) is out of scope for this
session and belongs to whichever session wires the Tauri `apps/desktop/src-tauri` backend to
`credmgrd` for real.

**Rejected.** Giving `graph.snapshot` an `if scope.holds(Capability::Admin) { skip
resolve_capability }` shortcut — this is exactly the "it should work" move
`12_BUILD_PLAN.md`'s own Phase 5 sentence and ADR-046 already foreclosed for hardware
keystores, applied here to authorization instead of biometrics: any caller that could
construct an `Admin`-holding scope (today, only a test fixture — but the whole point of
naming this gap is that "today" is exactly when it must not be built in) would see the entire
vault topology with no real login behind it. Blocking `graph.snapshot` entirely until the
session mechanism exists — rejected for the same reason ADR-039/041/042/043/046 each already
gave: the op is real, tested, and correct for the access model that exists now; the Svelte
canvas can be built against it today for whatever scope a real client resolves to, and will
simply see more once a real session mechanism lands, with no reshaping of this op required.

**Consequence.** `graph.snapshot`'s wire contract will not change when the session mechanism
is built — only what `resolve_scope` hands it as a scope will. Phase 6's UI work in this and
future sessions should build the canvas against `graph.snapshot` as-is, and should **not**
attempt to fabricate a "sees everything" caller anywhere outside a test fixture that is
explicit about doing so (as `crates/brokerd/tests/graph_snapshot.rs`'s own `admin_scope()` doc
comment now states).

**Test:** `crates/brokerd/tests/graph_snapshot.rs`, 6 tests, all real `ops::dispatch` calls
against a real (if unlocked-by-fixture-shortcut, per existing convention in this test
directory) `BrokerState` — no mocked authorization boundary.

---

## ADR-048 · `entry.rotate`/`entry.remove`/`entry.restore` built for real; the changelog-id-
addressed `entry.undo` and rotation-history restore stay named gaps, not stubs

**Context.** Sessions 5, 7, and 8's own `BUILD_LOG.md` entries each carried the same line
forward unaddressed: "`entry.remove`/`entry.rotate`... still untouched." `10_API_AND_MCP.md
§1/§2` lists both, plus `entry.undo` (`18_ENDPOINT_INDEX.md §1.6`: `POST /api/changelog/:id/
undo` → `entry.undo`, "`replace`/`keep-both` collision modes retained" from V1's
`changelog.js`). Building the first two surfaced that the third is not actually one op but two
different restore targets wearing one name — undoing a `rotate` means putting back the
*previous value*; undoing a `remove` means putting back the *entry itself* — and that `10 §1`'s
own `audit.tail`/`audit.get` (the ops an id-addressed undo would resolve `:id` against) are
**also unbuilt**, carried over from the same sessions. An `entry.undo` addressed by changelog id
has nothing to look the id up against yet.

**What this session established, that the docs left implicit.** Neither `entry.rotate` nor
`entry.remove` needs the vault's *cryptographic* unlock at all — both seal to the node's
**public** key only (identical to `entry.create`/`entry.update`, which already do this), and
removing/restoring an entry never leaves its owning node, so no re-encryption is ever needed
(unlike `node.seal`, which moves ciphertext to *orphan's* key and genuinely needs the node's
private key). The R1-locked gate on all three is therefore a **policy** choice, not a crypto
necessity — the identical policy `entry.update` already established: "a legitimate mutation
implies you could have read what you are replacing" (`06_ACCESS_GRAPH.md §3`), extended here to
rotating and removing for the same reason. `10_API_AND_MCP.md §1`'s binary framing ("`entry.
create` is permitted while locked... `entry.update` is not") is read as exhaustive by omission:
anything not explicitly whitelisted as locked-permitted defaults to requiring unlock.

**Decision — build what's real, name what isn't, three separate ops:**

- **`entry.rotate`.** `Capability::Update`, R1 → `VaultLocked`, F-9 generation-checked — the
  same gate `entry.update` already has. Retains the **previous ciphertext** as a plain file copy
  (`crates/store::paths::entry_history_env`, keyed by the pre-rotate generation) before
  overwriting, and sets a new `rotatedAt` field on `ManifestEntry` (`modified` still bumps too,
  but `rotatedAt` is rotate-specific so the UI can show "last rotated" apart from "last edited").
  The retained history is **not signed** — nothing restores from it yet, and the envelope's own
  AEAD tag already makes silent content-tampering detectable; there is no freshness claim to
  forge the way there is for a *removal's* recovery window.
- **`entry.remove`.** Same gate. Moves the entry's envelope into a new signed 7-day archive
  (`crates/store::entry_archive`, mirroring `archive.rs`'s whole-body-HMAC pattern from
  `manifest.rs`, not `archive.rs`'s own signed-digest-string one — the whole `RemovedEntryBody`,
  including the full `ManifestEntry` snapshot, is what the tag covers, so a restore can put the
  entry back with its original id/ref/type/sensitivity with no re-inference). Unlike a sealed
  *node*, there is no cold orphan copy behind a removed *entry* (`06_ACCESS_GRAPH.md`'s model has
  no per-entry orphan) — past the 7-day window, `entry.remove` is genuinely final.
- **`entry.restore`.** Addressed by `{node, entry}`, **not** a changelog-record id. `mode:
  "replace"` (default) refuses outright if a live entry has since reclaimed the removed name —
  exactly V1's `changelog.js` undo-delete behaviour, never a silent overwrite of whatever now
  holds that name. `mode: "keep-both"` restores it as `"<name> old"` (then `"<name> old 2"`, …)
  instead, so neither entry is ever lost. Collision handling is decided from the archive's
  retained snapshot (`entry_archive::peek`) **before** any file is moved, so a refused `replace`
  touches nothing — `peek` and `restore` share one expiry-checking helper
  (`read_verified_and_unexpired`) precisely so a caller can never see a past-window removal as
  restorable at peek time only to have the actual restore disagree.

**Deliberately not built this session:**

1. **An `entry.undo` addressed by changelog-record id.** `audit.tail`/`audit.get` don't exist yet
   to resolve `:id` against — inventing id-based addressing today would mean either a second,
   parallel storage of "what changed" (duplicating the hash-chained audit log's job) or a fake id
   scheme nothing else recognises. When `audit.tail`/`audit.get` land, an id-addressed `entry.undo`
   for a *removal* can be a thin wrapper: resolve `id → {node, entry}`, call `entry.restore`.
   Nothing built this session needs to change for that to work.
2. **Undoing a `rotate`.** The retained rotation history (`entry_history_env`) is write-only for
   now — nothing reads it back. A real "undo this rotation" needs its own restore path (distinct
   from `entry_archive`, since nothing was ever removed from the live manifest) and is better
   scoped together with `entry.history`'s read side (`18_ENDPOINT_INDEX.md §1.2`: `GET /api/
   credentials/:name/history` → `entry.history`), also still unbuilt.
3. **A vault-wide `deletedRefs` ledger.** V1's `store.js` used one to detect a *resurrected* ref
   showing up unexpectedly (an integrity check for `doctor`/`verify`), not to reclaim ref numbers
   — V2's `next_ref()` is already correct-but-non-reclaiming (Session 6's atomic counter) with no
   correctness gap this closes. Restoring a removed entry puts back its **original** ref (from
   the retained snapshot), matching V1's own undo-delete semantics exactly. A `doctor`-side
   resurrection check is future maintenance-op territory, not blocking anything built here.

**Rejected.** Building a generic "change record" abstraction (V1's `changelog.js` shape) just to
give `entry.undo` a uniform id-addressed interface across rotate/remove/create — rejected for
the same reason ADR-046/047 each already gave for their own deferred piece: it would mean
inventing a second parallel history mechanism *before* the audit log it should sit beside even
exists, precisely the "build the part with no missing dependency, name the rest" split this
codebase already applies at every phase boundary.

**Test:** `crates/store/src/entry_archive.rs` (9 unit tests: move/peek/restore round-trip,
day-6 restore, day-8 refusal + purge, tampered/wrong-key refusal, no-archive-not-found) and
`crates/brokerd/tests/entry_lifecycle.rs` (15 tests: rotate value-replace + history retention +
conflict + capability + locked refusal; remove manifest-removal + archive + conflict + not-found
+ locked refusal; restore same-name round-trip, `replace` collision refusal, `keep-both`
renaming, day-8 expiry, never-removed not-found, capability refusal) — 24 new tests, all real
`ops::dispatch` calls against a real `BrokerState`, no mocked authorization boundary.

---

## ADR-049 · `audit.tail`/`audit.get` built for real, plus the write-side gap they exposed:
every decision now actually gets audited, not just `TokenWorkdirMismatch`

**Context.** ADR-048 named `audit.tail`/`audit.get` as `entry.undo`'s missing prerequisite and
carried them forward, unbuilt, from Sessions 5/7/8. Starting on them surfaced something none of
those earlier BUILD_LOG entries had flagged: `10_API_AND_MCP.md §1`'s own invariant list
promises "every decision, allow or deny, appends one audit record and returns its id" — but
`crates/brokerd/src/server.rs`'s `handle_request` had exactly **one** call into
`credmgr_store::audit::append`, for the I-12 `TokenWorkdirMismatch` anomaly path alone. Every
ordinary `entry.reveal`, every `node_access_denied`, every `vault.unlock` — none of it was ever
written to the audit log. `audit.rs` itself (Phase 2) was real and fully tested; nothing upstream
of it in the broker had ever called it for a real decision. Building a *read* API over a log that
real traffic never populated would have been technically correct and practically empty.

**Decision — close the write gap first, generically, at one call site.** `server::
record_decision` is a new function, symmetric with the existing `record_anomaly`, called once at
the end of `handle_request` regardless of op or outcome: `actor` from the token id (or
`Origin` if none), `action` = the op name verbatim, `node_id` from `params.node` falling back to
the caller's own scope, `decision` = `"allow"`/`"deny"`, `detail` = a short static tag (reusing
`to_wire`'s own `"error"` vocabulary) on failure. Generic and op-agnostic **by construction** —
one call site instead of teaching every match arm in `ops::dispatch` to log itself, which would
have meant re-deriving the same five lines forty times and inevitably missing one on the next op
added. Best-effort, matching `record_anomaly`'s own established shape: a locked vault (no root
key yet) means logging silently no-ops rather than turning into a second denial of a request the
access graph already decided.

**A necessary, bounded signature change.** Returning the appended record's id to the caller (so
the wire response can carry `"audit": "a_…"` per `10 §1`'s own example) meant `handle_request`
could no longer return a bare `Result<Value, OpError>` — `OpError` is a closed, exhaustively-
matched enum every test in this workspace already asserts against directly
(`matches!(err, OpError::NodeAccessDenied { .. })`), and threading an id through every variant
just to carry one incidental value would have touched all of them for no benefit to what those
assertions actually test. `handle_request` now returns `(Result<Value, OpError>, Option<String>)`
— the ~10 existing call sites in `phase3_exit_gate.rs`/`phase5_gate.rs`/`isolation.rs` were
updated mechanically (`.unwrap_err()` → `.0.unwrap_err()`, or destructure at the `let`), with one
real behavioural fix along the way: I-12's own test had assumed the anomaly record was
necessarily the *last* line in that month's log, which stopped being true the moment every
request also gets a generic decision record — fixed by having the test find the anomaly record
by its own `action` field rather than by position, which is what the test was always actually
asserting.

**`audit.tail`'s three design choices, each grounded in something already established elsewhere
in this build rather than invented fresh:**

- **Plaintext, no root key, works while locked.** `AuditRecord` carries no secret (by
  construction — `never_records_a_value_field_by_construction`, Phase 2), so reading it back
  needs no more gate than `registry.json`/`manifest.json` already have (`07_TWO_FACTOR.md §2`'s
  "List / read metadata: — / — / —" row).
- **Filtered to the caller's own reachable set**, the identical `resolve_capability(...,
  Capability::List, ...)` per-node filter `node.list`/`whoami`/`graph.snapshot` already use
  (I-22's shape) — a record about a node the caller cannot even list never appears, not redacted,
  absent. This is also what caught a test-authoring mistake, not a code bug: an early draft read
  results back through a Global-scoped `admin_scope()` fixture and got zero records, because
  `06_ACCESS_GRAPH.md`'s R3 is direction-specific — every node reads Global, Global does not read
  its own descendants — the exact same finding ADR-047 already made for `graph.snapshot`. Fixed
  by reading back through a node-scoped reader, not by loosening the filter.
- **Redacted for `Origin::Agent` specifically, not for "every non-native origin."**
  `18_ENDPOINT_INDEX.md §1.6` says "always redacted for agents," and `credmgr_recent_changes`'s
  own doc row names exactly four fields for that feed (id, action, timestamp, actor) — `human-
  ui`/`cli`/`native` are each a human at the keyboard; `agent` is the one origin an LLM caller
  (the MCP surface) can carry. Because `06 §4`'s resolution order hardcodes `Origin::Agent` for
  both of its no-explicit-token cases (ADR-047's own finding, traced one level further here),
  every call through a real transport today gets the redacted shape; full detail is reachable
  only via an explicitly-issued non-agent token, which nothing on a real transport constructs yet
  — the same "correct now, more capable once the session mechanism lands" shape ADR-047 already
  established for `graph.snapshot`.

**`audit.get` refuses unconditionally, on the capability check alone, exactly like
`node.reparent`/`grant.create`.** `18_ENDPOINT_INDEX.md §1.6`: "full record needs presence." No
Phase 3/4/5 transport can ever set `presence_attested: true` (ADR-046's named gap), so the
positive path — one unredacted record by id — is refused via `PresenceRequired` regardless of
whether the id even exists, checked only after confirming the caller holds `Capability::Admin` so
a caller without it learns nothing about whether the id is real. Not a stub: the capability gate,
the op name, and the wire shape are all real; only the presence attestation itself is missing,
and Phase 5's native shell is what will eventually supply it — nothing about this dispatch arm
needs to change when it does.

**Rejected.** Threading the audit id through every `OpError` variant instead of changing
`handle_request`'s return type — touches far more call sites for a worse reason. Redacting
`audit.tail` for every origin except `Native` specifically — contradicts `18_ENDPOINT_INDEX.md`'s
own wording ("for agents," not "for everyone but native") and would make `human-ui`/`cli` origins
(neither of which is any more reachable today than `native` is, per ADR-047) indistinguishable
from `agent` for no documented reason. Building `entry.undo` now that its stated prerequisite
exists — still a distinct, larger feature (deciding what "undo" means for an arbitrary historical
change, not just a removal) that ADR-048 already scoped out; `audit.tail`/`audit.get` existing
removes the *blocker*, it does not by itself answer the remaining design question.

**Test:** `crates/store/src/audit.rs` (5 new unit tests: id uniqueness, `tail` newest-first with a
limit, `tail` walking backwards across a month boundary, `tail` on an empty vault, `get` by id and
by an unknown id, plus the existing field-set test updated for the new `id` field) and
`crates/brokerd/tests/audit_ops.rs` (8 tests, all real `server::handle_request` → `ops::dispatch`
round trips: every dispatched request is audited, newest-first ordering, redaction by origin,
cross-node visibility filtering, read-while-locked, the capability gate on each op, and `audit.get`'s
unconditional `PresenceRequired`) — 14 new tests, plus `credmgr_recent_changes` (MCP) and
`credmgr audit` (CLI) each proven end-to-end against a real subprocess and a real broker in
`crates/cli/tests/{mcp_integration,broker_integration}.rs`.

---

## ADR-050 · `grant.list`/`grant.create`/`grant.revoke` built; gated on `Capability::Admin`
resolved against `to`, not `from` — `revoke` genuinely executes, `create` is presence-blocked
like `node.reparent`; a real `GrantTarget` serde bug found and fixed along the way

**Context.** `10_API_AND_MCP.md §1` lists `grant.list|create|revoke` among the Phase 3 op
surface; `18_ENDPOINT_INDEX.md §1.3` marks the group "human + presence only"; `audit.get`'s own
comment (ADR-049) called out `grant.create` by name as a documented-but-unbuilt requirement —
"not a built precedent, just the same documented shape." This session closes that gap for all
three verbs.

**Decision — gate on `to`, not `from`.** `03_DATA_MODEL.md §6`: `Grant.to` is "the node being
opened" — the endpoint whose confidentiality boundary widens when the grant exists. All three
ops therefore resolve `Capability::Admin` against `to.nodeId()`, never `from`: administering
node B's exposure is B's administrator's call, matching the reasoning `access_denied_error`'s
own remedy text already implies ("A human can create a grant" — from the *reader's* side, but
the authority to expose lives with the node being read). This mirrors `node.seal`/
`node.reparent`'s own established self-admin pattern (`scope_for(target_node, Admin)`, R2) —
there is no broader "Global admin reaches every descendant" shortcut anywhere else in this
build, so none was invented here either.

**Two different Phase-3 answers, following the exact split ADR-047/048/049 already
established:**
- **`grant.list` is readable metadata, no presence.** A `Grant` carries no secret by
  construction (`03_DATA_MODEL.md §6`'s own type — `id`/`from`/`to`/`direction`/`scope`/
  `expiresAt`/`reason`, never a value), so listing needs no root key and works while locked —
  the same `List / read metadata` shape `audit.tail` already established, filtered to grants
  whose exposed (`to`) node this scope can `Admin` (the same reachable-node visibility filter
  `audit.tail`/`node.list`/`graph.snapshot` all use — I-22's shape, restated a fourth time).
- **`grant.create`'s positive path is unconditionally `PresenceRequired`, same as
  `node.reparent`.** `07_TWO_FACTOR.md §2`: "Create / modify a grant" needs a live global AND
  target-node gate session plus presence — Phase 3 has neither a per-node gate-session tracker
  for admin ops nor any transport that can ever set `presence_attested: true`. Every other
  invariant is validated for real first (reason ≥ 8 chars, orphan rejected as either endpoint
  per `03 §6`, `scope` restricted to exactly `03 §6`'s own type — `read`/`reveal`/`notes`, never
  `list`/`create`/`update`/`admin` — then the capability ceiling, then `resolve_capability`
  against `to`) so nothing about this dispatch arm needs to change once Phase 5 supplies a real
  presence attestation.
- **`grant.revoke` genuinely executes — no presence.** `06_ACCESS_GRAPH.md §6`: "Revocation is
  one click and takes effect on the next request — no re-encryption"; "Revoking is available in
  both Pro and Lite ... removing one is safety and is always reachable." `09_UI_UX_SPEC.md §10`'s
  own mockup shows a bare one-click **Revoke** with no 2FA field, unlike the create dialog's
  explicit `[ 2FA code ______ ]`. Revoking only *narrows* what a node can reach, so
  `Capability::Admin` on the exposed (`to`) node is the whole gate — the same substitution
  `node.seal`/`node.restore` already make for a destructive-looking-but-safe action — and this
  is the one op among the three whose positive path is real and tested today, not merely
  validated-then-refused.

**A real bug found and fixed: `GrantTarget`'s field names never actually matched the wire
shape.** `crates/core::registry::GrantTarget` carried `#[serde(tag = "kind", rename_all =
"camelCase")]` at the *enum* level — but serde's `rename_all` on an enum only renames variant
names, it does not reach into a struct variant's own fields (unlike a plain struct, where a
container-level `rename_all` does cover every field). The actual wire serialization was
therefore `{"kind":"node","node_id":"b"}`, not the `nodeId`/`entryId` `03_DATA_MODEL.md §6`'s TS
type (and `06_ACCESS_GRAPH.md`'s worked examples) specify. Nothing had ever caught this because
nothing before `grant.list` ever serialized a `GrantTarget` to real JSON — `crates/store`'s
round-trip tests go through the same (buggy-or-fixed) code symmetrically on both save and load,
so they could never notice a wire-shape mismatch against an external spec. Fixed by moving
`rename_all = "camelCase"` onto each variant individually (the pattern serde actually requires
for struct-variant fields), verified against the full `credmgr-core`/`credmgr-store` suites (no
regressions — confirming no other code depended on the broken shape) and against `grant.list`'s
own new wire-shape test, which is what surfaced it in the first place.

**Rejected.** Letting a Global-scoped Admin token reach every descendant node's grants
directly (skip the per-target `resolve_capability` filter) — would have been simpler to write
but reintroduces exactly the "Global reads its own descendants" shortcut ADR-047 already found
and rejected for `graph.snapshot`; there is no textual basis for treating grants specially.
Requiring `Capability::Admin` on `from` instead of (or in addition to) `to` — the endpoint
*receiving* access has no stated authority over the endpoint being exposed; the UI's own grant
dialog frames both sides but only the "To" node's confidentiality is what changes hands.
Rejecting `grant.revoke`'s presence-free design and matching `create`'s full gate instead — the
docs explicitly and repeatedly distinguish the two ("always reachable", "one click", no 2FA
field in the mockup); building it identically to `create` would ignore that distinction for no
documented reason.

**Test:** `crates/brokerd/tests/grant_ops.rs` (13 tests: the capability-ceiling check and the
`to`-node visibility/authority filter for all three ops, the documented `Grant` wire shape,
`create`'s reason/orphan/scope validation and its unconditional `PresenceRequired` once every
other invariant holds, and `revoke`'s real removal — including that a second revoke of the same
id is `NotFound`, not a silent double-success) plus two `crates/cli/tests/broker_integration.rs`
end-to-end cases (`grant ls`/`grant revoke` round-tripping a real grant through the compiled
binary and a real broker; `grant <from> --to ... --reason ...` failing specifically on
`presence_required`, not on some other validation error) — 15 new tests in total. No MCP tool
exists or is added for any of the three ops (`10_API_AND_MCP.md §3.1`'s tool table names none;
`FORBIDDEN_OPS` already lists `grant.create`/`update`/`revoke` and needed no change).

---

## ADR-051 · `node.create` built for real, gated on `Capability::Admin` resolved against the
parent, not presence-blocked — the missing prerequisite for demonstrating success criterion 6

**Context.** `18_ENDPOINT_INDEX.md` lists `node.create` as a documented op; nothing in
`crates/brokerd/src/ops.rs` ever implemented it. This was not previously named as deferred work
by any prior ADR (unlike the hardware keystores in ADR-046, or the session/login mechanism in
ADR-047) — it was simply missed, surfaced only while attempting Phase 7's demonstration
requirement for `01_CONCEPT.md §7` success criterion 6 ("a fresh V2 vault, created and populated
only through its own CLI/MCP/broker"): there was no live path to create the *nodes* half of
that claim at all, only the entries half.

**Decision — same substitution as `node.seal`/`node.restore` (I-21's pattern), not
`node.reparent`/`grant.create`'s unconditional `PresenceRequired`.** `07_TWO_FACTOR.md §2`'s
table does not name node *creation* at all (it names "Remove (seal) a node" and "Create /
modify a grant" specifically); the closest documented reasoning is `06_ACCESS_GRAPH.md §6a`'s
account of why *re-parenting* needs presence — "moving a node changes its ancestor set and
therefore what it can read — a grant by another name." A brand-new, empty node has no such
effect: it has no existing data whose reachability silently shifts, and R8 isolates it from
every other node the instant it exists, with zero configuration (`06 §8`'s own worked example).
Its risk profile is much closer to seal/restore (an administrative, immediately-reversible-ish
action gated by whether the caller's token legitimately holds `Capability::Admin` at all) than
to reparent/grant-create (which change what *existing* data is reachable). `05_THREAT_MODEL.md`'s
own agent-scope-widening row is specifically about grants ("Tokens are scope-immutable; grants
require `createdBy: 'human'` and a presence attestation") — node creation does not widen any
*existing* agent's scope, since nothing is reachable from a freshly created node until a
separate grant is drawn for it.

Gated on `Capability::Admin` resolved against the **parent** (`parentId`), not the new node
itself (which does not exist yet to resolve against) — administering what a project may spawn
underneath it is that project's administrator's call, the same "authority lives with the node
whose subtree changes" reasoning ADR-050 already applied to `grant.to`. Validated for real
before any mutation: reserved ids (`global`/`orphan`) rejected, duplicate ids rejected, unknown
parent rejected, depth cap (`03_DATA_MODEL.md §1`) enforced by deriving `(kind, depth)` from the
parent's own depth (0 → a new `Project` at depth 1; 1 → a new `Sub` at depth 2; 2 → rejected,
already at the cap) and then re-checked against `crates/core::registry::validate_registry` on a
scratch clone before the real registry is ever touched — reusing the invariant checker rather
than re-deriving "what makes a node shape valid" a second time in `brokerd`. A real node key is
generated and wrapped under the root key (`BrokerState::seed_node_key`) as part of the same
call, so a created node is immediately usable by `entry.create` — not a placeholder waiting for
a second step.

Not exposed as an MCP tool. `10_API_AND_MCP.md §3.1`'s tool table names no `node.*` operation at
all — `node.seal`/`node.restore`/`node.reparent` were already CLI/native-only by omission, and
`node.create` follows the same absence. Added to `FORBIDDEN_OPS` explicitly rather than left
implicit, since the list's own stated purpose ("the failure mode is a future session helpfully
adding one") is forward-looking, and a newly-introduced structural-boundary op is exactly the
kind of convenience a later session might be tempted to expose to an agent.

**A design gap found while implementing this, noted but not fixed here.**
`credmgr_core::access::resolve`'s R3 ("target is `global` → ALLOW") is not itself scoped to any
particular capability — the rule fires for *any* `capability` argument, including `Admin`, so a
token holding `Capability::Admin` for any reason at all can resolve Admin against `global`
regardless of which node it is otherwise scoped to. `06_ACCESS_GRAPH.md §1`'s own rule table
states R3's ALLOW the same unqualified way, so this is a documented property, not a
divergence between the doc and the code — but it means a future live token-issuance path
(ADR-047's still-missing session/login mechanism) will need to decide deliberately whether
`Capability::Admin` should really be R3-universal, or whether R3 should be narrowed to
read-type capabilities before any real login path makes an Admin-scoped token reachable
outside test fixtures. Currently inert: Phase 3 has no live way for anything but a test fixture
to mint a token at all (`broker_integration.rs`'s own fixture doc already says so), so this is
not reachable through any shipped client today. Named here so the next session that builds real
token issuance opens with it instead of re-deriving it.

**Rejected.** Presence-blocking `node.create` unconditionally, matching `node.reparent`'s shape
— would have made it impossible to demonstrate success criterion 6 at all in a non-interactive
environment (the same limitation ADR-046 already accepted for the hardware keystores), and
nothing in the threat model or `07_TWO_FACTOR.md`'s table actually names node creation as
needing it; doing so anyway on the theory that "it sounds similar to reparenting" would be
inventing a requirement rather than reading one. Gating on `Capability::Admin` resolved against
the *new node's own id* instead of the parent — meaningless, since the node does not exist yet
to resolve against, and would have made the very first node under any given parent uncreatable
by construction. Skipping `validate_registry` and hand-rolling the depth/kind checks alone —
would have duplicated logic `crates/core` already owns and tests, the same mistake ADR-001
exists to prevent generally.

## ADR-052 · `artifact-hardened` stamps reconciled to commits that actually resolve in this
repo (Phase 7 gate item)

**Context.** `12_BUILD_PLAN.md`'s Phase 7 exit gate requires "every doc's `artifact-hardened`
stamp matches its current commit." All 21 docs in `docs/` carried a stamp citing `fb8bf99` —
which does not exist in this repository (`git cat-file -t fb8bf99` → `fatal: Not a valid object
name`). The design corpus was hardened (Pass 1–3, `2026-08-04`/`05`) in whatever context
preceded this repo's unification commit, `d15a5c7` ("CredMgr — v1 (working product) and v2
(Vault Next design)") — the stamps carried that context's commit forward into a history that
never contained it.

**Decision.** Reconcile by provenance, not by re-running Pass 2/3 wholesale — a full re-audit of
the corpus is Phase 8's stated job (`12_BUILD_PLAN.md` Phase 8: "full-corpus re-verification,
not a scoped doc list like every phase before it"), not this gate item's. Two buckets, decided
by `git diff d15a5c7 HEAD -- <file>`:

- **14 docs unchanged since `d15a5c7`** (`00`, `02`, `03`, `04`, `05`, `07`, `09`, `10`, `13`,
  `15`, `17`, `18`, `20`, `21`): content is exactly what Pass 2/3 approved, only the pointer was
  foreign. Re-anchored `@ fb8bf99` → `@ d15a5c7` — same approval, same date, a real commit.
  `00_README_START_HERE.md`'s stamp used a literal `HEAD` token instead of a sha; dropped in
  favor of the same concrete anchor, since `HEAD` is tautologically "current" and can never fail
  the gate's own check.
- **6 docs genuinely edited since `d15a5c7`** (`01`, `06`, `08`, `12`, `14`, `16`): each diff
  read in full before re-stamping. All six are self-consistent corrections or additions with no
  regressions found: `01_CONCEPT.md` fixed the success-criterion-6/no-migration contradiction
  (`2026-08-08`, already self-noted inline); `06_ACCESS_GRAPH.md` added §8's worked
  belongs-to-no-project infra example; `08_FIELD_MODEL.md` replaced a real-looking example IP
  with an RFC 5737 documentation-range address (`203.0.113.4`) and clarified an example key is a
  placeholder; `12_BUILD_PLAN.md` recorded the Phase 6 UI pull-out and the Phase 7/`01 §7`
  corrections (both already self-noted inline); `14_DECISIONS.md` (this file) voided ADR-028/034
  against the no-migration decision and added ADR-045–051; `16_CROSS_PLATFORM.md` added the
  ADR-035 MSRV note. Re-anchored `@ fb8bf99` → `@ 6ee1e5f` (HEAD at reconciliation time) with
  today's date; known-risk lists (`AR-1..AR-6`) carried forward unchanged since nothing found
  here touches them.
- **`11_MIGRATION.md`** already cited a real, correct commit for its rewrite in its date field
  but omitted the sha itself. Its sole post-`d15a5c7` commit, `9e0937e`, is timestamped
  `2026-08-05 06:07:17 +0330` — matches the doc's own "rewritten `2026-08-05`"
  self-description exactly. Added the sha for consistency with every other stamp; no other
  change.

**Not done here, and why.** No content was re-audited beyond the six real diffs above — the
other fourteen docs were not re-read line-by-line against current code reality as part of this
pass. That is Phase 8's job by design (Opus, max effort, full corpus). Keeping this ADR's scope
narrow is deliberate: conflating "the pointer now resolves" with "the content was re-verified"
would be exactly the kind of overclaim this file's own review history exists to prevent.

**Consequence.** `12_BUILD_PLAN.md` Phase 7's stamp-reconciliation exit-gate item is satisfied
by construction — every stamp in `docs/` now cites a commit `git cat-file -t` resolves in this
repository. Approval status and known-risks are unchanged for every doc; this ADR changes
provenance pointers only.

**Test:** `crates/brokerd/tests/node_ops.rs` (10 tests: the capability-ceiling check, denial
when Admin is held but does not reach the specific parent, real creation of both a depth-1
project under `global` and a depth-2 sub-node under a project, a freshly-created node's default
isolation from its siblings (R8) and a freshly-created depth-2 sibling's default sharing (R6) —
both directly exercising criterion 6's actual claim — reserved/duplicate/unknown-parent/depth-cap
rejection, and that a created node is immediately usable by a real `entry.create` call). CLI
wiring (`credmgr node create <id> --label <label> --parent <id>`) exercised end-to-end as part
of the success-criteria demonstration tests this same session added (see `BUILD_LOG.md`).

---

## ADR-053 · `node.restore` authorises against the sealed node, not merely against "the token
carries Admin somewhere" (Phase 8 audit — a real cross-node hole, closed)

**Context.** `node.seal` gates on two things: the token holds `Capability::Admin`, *and*
`resolve_capability(scope, target_node, Admin)` allows. `node.restore` — the exact inverse
operation on the exact same data — gated on only the first. Its comment explained why:
*"The node no longer has a registry entry to resolve() against (that's the point of having
sealed it) — `Capability::Admin` held by the token is the whole gate here."* The premise is
true; the conclusion did not follow.

The result was an asymmetry an attacker gets to choose: an Admin token scoped to project `b`
is correctly refused when it tries to seal project `a` (R8), but was **accepted** when it
asked to restore `a`. `b` never reads a byte of `a` — so this is not a confidentiality leak —
but it lets one project unilaterally undo another's security action, moving values that were
deliberately sealed to human-only (`00_README_START_HERE.md`: *"no agent, no CLI, no
automation, ever"*) back into agent reach for whoever can read `a`. Seal is one of the four
promises; a promise that any Admin token can revoke is not one.

Found by the Phase 8 audit's mechanical sweep — every arm of `ops::dispatch` tabulated for
whether it performs *both* a `scope.holds` ceiling check and a `resolve_capability` graph
check. Two arms had a ceiling check and no graph check: `audit.get` (correct — it
unconditionally returns `PresenceRequired`, so there is nothing to resolve and it fails
closed) and this one. Confirmed empirically before any fix was written:
`i21b_restore_is_refused_to_an_admin_token_from_an_unrelated_node` failed with
`Ok({"node": "a", "restored": true})`.

**Decision.** `node.restore` makes the same `resolve_capability(scope, target_node, Admin)`
call `node.seal` makes, against the same node id, *before* touching the sealed record.

It resolves correctly **because** the node is absent, not in spite of it:
`Registry::is_strict_ancestor` returns `false` for a node it cannot find, so R4/R5/R6 cannot
fire; R3 needs the target to *be* Global; R7 needs a grant against a node that is gone. The
only rule that can still allow is **R2** — subject == target, the node restoring itself,
which is exactly how I-21's legitimate path has always worked. Everything else lands on R8.

**Rejected.** *Resolving against the sealed node's recorded parent*, the way ADR-051 has
`node.create` resolve against `parentId` — the obvious symmetry, and wrong here. For a
depth-1 node that parent is Global, and R3 allows **every** node **every** capability against
Global, so a parent-based check would have re-admitted precisely the caller this ADR closes
out. ADR-051's permissiveness is sound for its own case (a brand-new, empty node shifts no
existing data's reachability) and unsound for this one. *Re-inserting the node into a
temporary registry view so the full rule set could run against its original position* —
strictly more faithful, materially more code, and it buys only the ancestor cases that the
paragraph below deliberately declines. *Leaving it and documenting the risk* — the fix is
nine lines and reuses an already-tested call; a known-hole entry would have been a choice to
ship a weaker guarantee than the one the corpus advertises.

**Consequence.** An ancestor holding Admin can no longer restore a sealed descendant, because
`is_strict_ancestor` cannot see the sealed node to establish the relationship. This is a real
narrowing, in the safe direction, and consistent with the model's own default (*"parents do
not read their children unless explicitly enabled"*). The node itself restoring itself — the
only path any test, CLI flow or documented procedure has ever used — is unaffected. If
ancestor-restore is ever wanted it needs the temporary-registry-view approach above plus its
own explicit decision, not a quiet relaxation of this check.

Residual, accepted: a caller holding Admin on *some* node still distinguishes "a sealed node
by that name exists but I am denied" (`node_access_denied`) from "no such sealed node"
(`not_found`). `node.seal` has the same shape. Not worth collapsing into one error — it would
cost the legitimate NotFound/`ArchiveExpired` distinction that I-21's day-8 assertion depends
on, to withhold the existence of a node id the caller very likely already knew.

**Test:** `crates/brokerd/tests/isolation.rs::i21b_restore_is_refused_to_an_admin_token_from_an_unrelated_node`
— seals `a` from `a`'s own Admin token; asserts as a baseline that `b`'s Admin token cannot
seal `c` (so the test cannot pass merely because `b`'s token is weak); asserts `b` is refused
`node.restore` on `a`; asserts the refusal is *total* (node still absent from the registry,
sealed entry still in orphan — not a half-restore); then asserts `a`'s own token still
restores `a`, so the fix is an authorisation change and not a regression of I-21. Written to
fail first, and it did.

---

## ADR-054 · `maintenance.verify|doctor|backup` — the exact three ops `10 §1` already named,
scoped against V2's actual model rather than ported from V1's flat vault

**Context.** `docs/10_API_AND_MCP.md §1`'s op list already names the three members literally —
`maintenance.verify|doctor|backup` — and `18_ENDPOINT_INDEX.md §1.4` cites the Pass 2 findings
each one absorbed: `verify` "now also checks manifest HMACs + generation (F-2/F-3)", `doctor`
"gains `--rebuild-registry` (F-10)", `backup` "now automatic daily + pre-destructive (F-16)".
So this was never an open naming question — the open question was always *build them*, against
primitives that (per ADR-039/`04 §7`) were deliberately left unwired until a session existed to
decide what encrypts a backup and what a rebuild candidate is reconstructed from. Two of the
three primitives already existed, fully tested, never called by any live op:
`crates/store::backup::{select_files, pack, unpack, create_backup}` (ADR-039) and
`crates/store::rebuild::{diff, apply}` (F-10's own module). Neither `maintenance.*` nor a
"backup encrypt" call site existed anywhere in `crates/brokerd`.

**V1 survey (`v1/lib/store.js`), and which parts do not port.** V1's `verifyIntegrity` checks a
checksum sidecar, index↔vault consistency (orphaned vault entries), and ref integrity (duplicate
active refs, refs resurrected from `deletedRefs`). `healStore`/doctor fixes duplicate/missing
refs, resurrected-ref cleanup, unregistered categories, and backfills the checksum. `backup` tars
`index.json` + `vault.age` (+ the master key if asked) and age-encrypts the tar, with retention
pruning (default 14).

Two of V1's doctor fixes have **no V2 analogue, by construction, not by omission**:

- **Duplicate/resurrected refs.** V1's refs are reused after deletion (hence `deletedRefs` and
  the reuse-collision class of bug). V2's `next_ref()` (Session 6) is a monotonic, vault-global,
  non-reclaiming counter — ADR-048 already noted this "no correctness gap" in passing. A ref
  collision is not a state `doctor` can ever find, because nothing in V2 can produce one.
- **Unregistered categories.** V1 has a registered-category list; V2 has none — `CLAUDE.md`:
  "Fields have free-text labels. There are no predefined field names." There is nothing to
  register.

The rest maps, but not 1:1 — V2's integrity story is already stronger than V1's checksum sidecar
(manifest HMAC + registry cross-binding, F-2/F-3; `vaultGeneration` rollback detection, F-3) —
so `maintenance.verify` mostly *reads back* checks the write path already enforces, plus the one
thing nothing currently checks *proactively*: that a manifest and its registry-recorded binding
still agree, and that a node's envelope files and its manifest still agree with each other
(V1's "orphaned vault entry" check, renamed — `orphan` already names a sealed-node state in V2,
so this report calls the condition **dangling** instead, never "orphaned").

**Decision — three ops, CLI/native-only (none MCP-exposed), each gated per its own risk, in this
dependency order: `backup` before `doctor --rebuild-registry`, which needs a backup to
reconstruct from.**

### `maintenance.verify`

Read-only. `Capability::List`, filtered to the caller's reachable node set — the identical
`resolve_capability(..., Capability::List, ...)` per-node filter `node.list`/`audit.tail`/
`graph.snapshot` already use (ADR-047/049's established shape), so a caller never learns that an
inaccessible node even exists, let alone whether its manifest verifies. For each reachable node:
loads the manifest via the existing `credmgr_store::manifest::load` (HMAC-checked) and
`verify_cross_binding` against the registry's recorded `(generation, hmac)` (both already built,
F-2/F-3) — a failure here is reported, not thrown, so one bad node doesn't abort the whole
report. Then a **dangling-file check**, new this session: every `entries/*.env` file with no
matching manifest entry id (dangling envelope), and every manifest entry with no matching
envelope file (missing envelope) — the direct V2-shaped analogue of V1's orphan check, under a
name that doesn't collide with the sealed-node meaning. Returns
`{ ok, nodesChecked, errors: [{node, detail}], warnings: [{node, detail}] }`. A tampered manifest
(`ManifestTampered`, i.e. its *own* HMAC fails) is an **error**, never auto-corrected by this op —
`verify` only reads.

### `maintenance.doctor`

`Capability::Admin`, resolved against **each node being healed** (`resolve_capability(scope,
node_id, Admin)`, the same self-admin pattern `node.seal`/`node.create` already establish) —
repairing a node's signed metadata is a structural operation, not an ordinary content write, so
it sits at `entry.update`'s tier's, not below it. `params.apply` (default `true`; `false` runs
the identical scan and returns what *would* change, touching nothing — V1's own dry-run
convention, kept). Runs `verify`'s scan first, then applies exactly one class of fix:

- **Cross-binding resync.** A manifest that verifies under **its own** HMAC, but whose
  `(generation, hmac)` the registry has stale (a crash or partial write between the two files,
  which `04 §6a`/F-3 name as the exact scenario cross-binding exists to catch) is safe to
  re-record — the manifest itself already proves what it claims. The registry's binding for that
  node is rewritten to match.
- **What doctor explicitly refuses to "fix."** A manifest that fails **its own** HMAC
  (`ManifestTampered`) is left alone and reported as an unfixable error. Re-signing
  attacker-modified (or corrupted) content as though it were legitimate would launder the
  tamper, not repair it — the one thing this op must never do. The only path back from a
  genuinely tampered manifest is `--rebuild-registry` (which reconstructs from a *backup*, not
  from the tampered file) or manual operator intervention.

**`--rebuild-registry`** (`params.rebuildRegistry: true`). `PresenceRequired` unconditionally —
matching `audit.get`/`grant.create`/`node.reparent`'s established shape (the real gate, on the
only surfaces Phase 3–5 have, none of which can ever set `presence_attested: true` yet; nothing
about this arm needs to change once Phase 5's native shell can). Behind that gate, for real: locates
the most recent file under `paths.backups_dir()` matching this session's `maintenance.backup`
naming convention, decrypts it with the supplied `params.passphrase` (see `maintenance.backup`
below — the same passphrase convention, since a rebuild candidate has to come from a
backup encrypted the same way), unpacks it (`store::backup::unpack`), and reads its bundled
`registry.json` as the **candidate** `RegistryDocument`.

**Revoked-grant ids: operator-supplied, not audit-log-mined — checked against the live code, not
assumed.** `store::rebuild::diff`'s `resurrected_revoked_grants` parameter (I-20, already built)
was always a plain caller-supplied `&HashSet<String>` — discovering *which* grant ids were
revoked was never that function's job. The first draft of this ADR assumed `server::
record_decision`'s generic per-request audit write (ADR-049) would carry a revoked grant's id
somewhere queryable; tracing the actual function found otherwise: it records `node_id` from
`params.node` (falling back to the *caller's own* scope when absent) and a `detail` string only
on **failure** (an error tag) — `grant.revoke`'s own params are `{id}`, carry no `node` field,
and its success path leaves `detail` empty. There is no structured field an audit-log scan could
key on today. Rather than widen `record_decision`'s generic shape for one caller (a cross-cutting
change to every op's audit record, well outside three ops' scope), `maintenance.doctor`'s rebuild
takes `params.knownRevokedGrantIds: string[]` directly — the operator, who is already the one
reviewing the diff and supplying `confirm: true` before anything is written, supplies the ids
they know were revoked (from their own reading of `credmgr audit`, or memory). This is what
`rebuild.rs`'s own function signature already expected the caller to provide; assuming something
must compute it automatically was the wrong reading of that module's design, caught by tracing
`record_decision` before writing code against the assumption.

Shows the diff; applies only when `params.confirm: true` is also set (a second explicit flag, not
the presence gate alone, matching F-10's "shows a full diff... before writing" as a distinct step
from authorising the rebuild at all). Records the rebuild in the audit log — automatically, via
`record_decision`'s existing generic per-request logging
(ADR-049); no special-cased logging needed here.

### `maintenance.backup`

`Capability::Admin` resolved against `GLOBAL_ID` — a whole-vault snapshot has no single owning
node to resolve against (unlike `verify`/`doctor`, which act node-by-node); Global is the one
node every reachable scope can resolve *something* against, and Admin-over-Global is the closest
existing shape to "vault owner." **This inherits R3's known permissiveness** (`access::resolve`'s
R3 arm allows *any* capability, including Admin, against `target == GLOBAL_ID`, unqualified —
the exact property ADR-051 already found and left "not fixed here", since nothing before now
could mint a live Admin-holding token outside a test fixture to exploit it). It is still correct
to gate this way *today*, for the same reason ADR-051 accepted it for `node.create`'s parent
check: currently inert. It stops being inert the moment ADR-056's session mechanism can issue a
real Admin token — that ADR is where R3 actually gets narrowed or left, deliberately, not here.

Calls `store::backup::create_backup` (unchanged, ADR-039) to produce the selected+packed bundle
bytes, then encrypts them — the call ADR-039 left for "whoever wires this up next" to make.
**Encrypted to an operator-supplied backup passphrase (stdin only, never argv — matching
`credmgr set`'s convention), stretched via Argon2id, parameters identical to
`SoftwareKeystore`'s (`m=256 MiB, t=3, p=4`, `16 §4.4`) so this doesn't invent a second KDF
policy** — new fresh salt per backup, stored in the output file's own header alongside the
ChaCha20-Poly1305 nonce, so a backup file is self-describing and restorable with **only** the
passphrase, independent of anything else surviving (the actual disaster-recovery requirement).

**Rejected: encrypting to a key derived from the root recovery code instead** (`04 §7`'s other
named option). Traced the live code path before choosing: `crates/core::recovery`'s
`wrap_root_with_recovery_code`/`generate_recovery_code` are fully built and tested, but **called
by nothing outside their own test module** — no live path writes `root.wrap.recovery` for a real
vault. `09_UI_UX_SPEC.md §12`'s first-run flow ("1. Create vault — name.") is where a recovery
code would first be generated and shown to an operator, and first-run/vault-creation is Phase
6/UI territory this backend-finish pass explicitly does not touch. Building `maintenance.backup`
against a wrap that may not exist on a given vault would be silently assuming a UI flow that
hasn't shipped. A backup passphrase has no such dependency: the operator supplies it fresh (or
reuses one they remember) at the moment they run `credmgr backup`, needing nothing else to exist
first. **Also rejected: an asymmetric backup keypair, public half cached on disk, private half
re-derived from the recovery code only at restore time** — the technically cleaner answer (it
would let backup-creation run unattended with no human present, which a passphrase-gated design
cannot) — but it has the exact same live-recovery-code dependency as the option above, plus a new
persistent artifact (`keys/backup.pub`) with no code path that writes it yet either. Worth
revisiting once vault creation is real; not invented here to route around that gap.

**Deliberately not built this session — automatic/scheduled firing (F-16's "daily... and before
every destructive operation").** ADR-039 already split this: "firing on a *timer* needs a
running process with a clock... that is `crates/brokerd`'s job." No scheduler/timer exists
anywhere in `crates/brokerd` today (confirmed — no cron, no `tokio::time`, no background loop of
any kind), so "automatic daily" has no process to live in yet, independent of anything this
session adds. This session ships the op itself, real and callable; a future session that adds a
scheduler calls it, unchanged, the same relationship `create_backup` already has to `maintenance.
backup` today. Because `maintenance.backup` is always operator-invoked today (CLI, a human
present to supply the passphrase), the "unattended encryption" tension the rejected asymmetric
design would have solved does not yet exist in practice — it starts to matter only once
something *else* calls this op without a human at the keyboard, which nothing does yet.

Retention: prunes the oldest backups beyond `params.retain` (default 14, matching V1's exactly),
only among files matching this op's own naming scheme (`credmgr-backup-<unix-ts>.enc`) — a
manually renamed or placed file is never a pruning candidate, same safety property V1's own
`retain` logic already had.

**MCP exposure: none of the three.** Not in `10 §3.1`'s tool table by the same "CLI/native-only
by omission" precedent `node.seal`/`node.restore`/`node.create` established before ADR-051 made
`node.create`'s omission explicit — made explicit here too, for the same stated reason
(`10 §3.2`'s own header: "the failure mode is a future session helpfully adding one"). All three
added to `FORBIDDEN_OPS` in `crates/mcp/src/tools.rs`: `doctor`/`backup` because they mutate
vault-wide state an agent must never trigger; `verify` because, even read-only, its errors can
name a specific security-relevant condition (a tampered manifest) that belongs in front of the
human via the CLI, not silently in an agent's context window.

**Rejected — porting V1's dry-run-by-default (`healOpts.apply !== false`).** V2's `doctor`
defaults `apply: true` (matching every other mutating op in this codebase, which act unless
told not to) rather than V1's default-dry-run — because unlike V1's fixes (which include the
now-impossible ref-collision case), every V2-era fix this op performs is a **provably safe**
resync of already-self-verifying data; there is no fix here a default-apply could get wrong in a
way `--apply false` would have caught, the way a wrong ref-reassignment plausibly could have in
V1's broader fix set.

**Test:** inline `#[cfg(test)]` unit tests, matching this crate's existing convention (every
other `crates/store` module — `backup.rs`, `manifest.rs`, `rebuild.rs` — tests itself the same
way; `crates/store/tests/` is empty and stays that way): `crates/store/src/verify.rs` (dangling/
missing envelope detection, 5 tests), `crates/keystore/src/backup_passphrase.rs` (encrypt/decrypt
round trip, wrong-passphrase and tampered-blob refusal, 6 tests), `crates/brokerd/src/
maintenance.rs` (backup file naming/discovery/retention, rebuild-candidate loading from a real
encrypted backup, 11 tests) — 22 new store/keystore-layer tests. Plus
`crates/brokerd/tests/maintenance.rs` (20 tests, all real `ops::dispatch` calls against a real
on-disk vault written via `registry_file::save`/`manifest::save`, not the in-memory fixture
shortcut: clean-vault report, dangling/missing/cross-binding/tampered-manifest detection, doctor's
apply-vs-dry-run and its refusal to resign a tampered manifest, `--rebuild-registry`'s capability-
before-presence ordering, backup's real encrypted output and retention pruning) — plus
`crates/mcp/tests/i13_tool_registry.rs`'s existing walk confirming all three stay absent from the
MCP surface.

---

## ADR-055 · `entry.undo` — a real, forward-only undo for both `remove` and `rotate`,
addressed by audit id, never a replayed-backward audit log

**Context.** ADR-048 named `entry.undo` addressed by changelog/audit-record id as its own
deferred piece, blocked on `audit.tail`/`audit.get` (ADR-049 closed that gap) and on a real
design question it explicitly declined to answer: *"deciding what 'undo' means for an arbitrary
historical change, not just a removal."* `10_API_AND_MCP.md §1`/`§3.1` both already name the op
(`entry.undo`, `credmgr_undo`) and its shape (`{node, entry}` for a removal's own recovery
window, `keep-both` collision mode retained from V1) — what remained undecided was specifically
the *rotate* case, and the mechanics of id-based addressing now that the audit log genuinely
holds decisions to address.

**Decision 1 — forward, never backward.** Undoing a change is itself a new, audited mutation
that puts the *content* back — never a rewrite, replay, or truncation of the audit chain itself.
`14 §`ADR-049 (append-only, hash-chained: "a removed or edited line changes the hash the *next*
line's `prev` must equal") exists specifically so the log cannot be quietly rewritten; an undo
mechanism that worked by unwinding audit entries would be exactly the capability the hash chain
is built to make impossible, applied by the vault's own "helpful" feature instead of an attacker.
`entry.restore` (ADR-048) already established the pattern for removal: restoring puts the entry
back **and appends a new `entry.restore` record** — the original `entry.remove` record is
untouched, still there, still provably the thing that happened. `entry.undo` for a rotate follows
the identical shape: it performs a **new rotate**, back to the previous value, itself producing a
new manifest generation and a new audit record. Nothing is ever erased.

**Decision 2 — addressed by `{node, id}`, not `id` alone.** `id` alone would mean the target node
isn't known until *after* looking the record up — but every other mutating op in this codebase
checks capability against a caller-supplied node **before** touching anything else, and
`audit.get`'s own design (ADR-049) checks the capability gate before ever confirming an id is
real, "so a caller without it learns nothing about whether the id even exists." Requiring `node`
keeps `entry.undo` in that same shape: authorise against the caller-supplied node first, then
look the record up and confirm `record.nodeId == node` (a mismatch — wrong node, or a guess at
another node's record — is `not_found`, indistinguishable from a bogus id, never a hint). The
caller undoing something it just did already knows which node it happened in; asking for it is
not a real burden, and building yet another oracle-shaped code path is a real cost.

**Decision 3 — a necessary, bounded audit-record extension.** Resolving `id → {action, node,
entry}` needs the audit record to actually carry an entry id — `server::record_decision`
(ADR-049) captures `node_id` from `params.node` but has no equivalent for the entry. Two fields
added to `AuditRecord`/`NewEvent`, both `#[serde(default)]` so older log lines (none exist in any
shipped vault, but the format must not assume that) parse as `None` rather than failing to
deserialise:
- `entry_id: Option<String>`, from `params.entry` — mirrors `node_id`'s existing `params.node`
  extraction exactly, same generic call site, no per-op special-casing.
- `generation: Option<u64>`, from the op's own **response** on success (`result["generation"]`)
  — every mutating op already returns its new generation in its wire response (`entry.rotate`/
  `remove`/`restore` all do); `record_decision` just also copies it into the audit record. Purely
  additive and generic: an op whose response has no `generation` field simply leaves this `None`.

Both fields are internal to how `entry.undo` resolves a record — `audit.tail`'s redacted (agent)
shape is unchanged (still exactly `id`/`action`/`timestamp`/`actor`, ADR-049); the full shape
gains two fields nothing currently reads over the wire.

**Decision 4 — a real gap found while designing the rotate case: rotation history retained the
ciphertext but never the metadata needed to restore it correctly.** `entry.rotate` (ADR-048)
writes the pre-rotate envelope's raw bytes to `entry_history_env` — enough to prove *that* a
prior value existed, not enough to restore it *correctly*: the live manifest entry's
`sha256`/`entryType`/`sensitivity` all describe the **current** (post-rotate) plaintext, and
nothing retained what those fields were *before*. Restoring only the ciphertext while leaving
those fields pointing at a different plaintext would leave the manifest internally
self-contradictory — a real correctness bug, not an acceptable gap, the moment something actually
reads this history back for the first time.

**Fix, mirroring `entry_archive.rs`'s own established split exactly** (raw envelope in one file,
signed metadata snapshot in a sibling): a new module, `crates/store::rotation_history`, and a new
path, `paths.entry_history_meta(node, entry, generation)` (`.../archive/entry-history/<node>/
<entry>/<generation>.json`, sibling to the existing `.env` file — `entry_history_env` itself is
untouched, still the raw ciphertext, so this is additive, not a breaking format change to
anything already written). `RotationHistoryBody { nodeId, entry: ManifestEntry, generation,
recordedAt }`, whole-body HMAC-signed under `HKDF(RK, "rotation-history/" + nodeId + "/" +
entryId)`, same shape as `RemovedEntryBody`'s tag. `entry.rotate`'s dispatch arm now saves this
snapshot (the **pre-rotate** `ManifestEntry`, read from the manifest before mutating it)
alongside its existing raw-bytes write — one additional call, no change to what was already
tested. No expiry window (unlike the 7-day removal archive): nothing purges rotation history
today, and inventing a retention policy for it wasn't asked for and isn't blocking anything.

**`entry.undo`'s two branches, both `Capability::Update`-gated (R1 → `VaultLocked`, F-9
generation-checked) against the caller-supplied node — matching `rotate`/`remove`/`restore`'s
own established gate exactly:**

- **`action == "entry.remove"`.** Thin wrapper, exactly as ADR-048 anticipated: resolve
  `record.entryId`, call the same internal restore logic `entry.restore`'s own dispatch arm uses
  (extracted into a shared function so there is exactly one implementation, not two that could
  drift), with `mode` from `entry.undo`'s own params (`replace` default, `keep-both` retained).
- **`action == "entry.rotate"`.** Resolve `record.entryId` and `record.generation` (the
  **post**-rotate generation that specific rotate produced); the pre-rotate generation is
  `record.generation - 1` — always exact, because every mutating write on a node bumps its
  manifest generation by precisely one (`state::update_manifest_entry`/`insert_manifest_entry`,
  F-9's concurrency model). Loads the retained snapshot (`rotation_history::load`) and the
  retained ciphertext (`entry_history_env`, same generation key) from that pre-rotate point,
  writes the ciphertext back as current, retains what's **currently** live (about to be
  superseded again) into a fresh rotation-history slot at the current generation — symmetric with
  every ordinary rotate, so undoing an undo works the same way, forever, with no special case —
  and updates the manifest entry's `sha256`/`entryType`/`sensitivity` from the restored snapshot
  (content-derived, and the restored content is byte-identical to what produced them) while
  `modified`/`rotatedAt` become `now` (this is a new mutation, not a time-travelled old one).
- **Anything else** (`entry.create`, `entry.update`, any `node.*`/`grant.*` action) —
  `OpError::NotUndoable`, naming which two actions are undoable. `entry.update` in particular is
  deliberately out of scope: it has no retained-history mechanism at all (only `rotate`/`remove`
  do), and inventing one is a real, separate feature this ADR does not scope.
- **A record whose own `decision` was `"deny"`** (the action never actually happened) —
  `OpError::NotUndoable` as well; there is nothing to undo.

**Rejected.** *Storing the pre-rotate snapshot inside the audit record itself*, avoiding a new
store module — the audit log's own contract (ADR-049's module doc) is "never records a value
field by construction" and the log is meant to be a redactable-for-agents read surface; embedding
a full manifest-entry snapshot (name, sensitivity, etc., all more detail than the redacted shape
ever shows) into every rotate's audit line would leak metadata through a surface designed to
withhold it. *An `entry.undo` that works by decrypting and comparing plaintext values* — needs
the vault unlocked for a rotate-undo (rotate/remove/restore all deliberately don't, ADR-048), and
buys nothing: the ciphertext being put back is the exact bytes that were live before, proven by
the same AEAD tag that already protects it, not something that benefits from a plaintext-level
comparison. *Reusing the changelog-id shape from V1's `changelog.js`* — V2 already has a
hash-chained audit log serving the identical purpose (ADR-049); a second, parallel "change
record" abstraction was already rejected once for this exact reason (ADR-048's own "Rejected"
section) and rejecting it again here would be re-deriving the same answer.

**MCP exposure.** `credmgr_undo` is already named in `10_API_AND_MCP.md §3.1`'s documented tool
table (`"Within the recovery window; keep-both collision mode retained from V1"`) and is
**not** on the forbidden list — `crates/mcp/src/tools.rs`'s own module doc already flagged this
as "carried over... as unbuilt," waiting for exactly this op. Wired up as part of this session,
mapped straight to `entry.undo`, no new capability tier: undoing is the same `write` capability
`credmgr_rotate`/`credmgr_remove` already carry.

**A necessary side-fix found while testing "undo of an undo": `audit.tail`'s own non-agent
response shape never carried the two new fields.** `record_decision` populates `entryId`/
`generation` on every `AuditRecord` (Decision 3, above) — but `ops.rs`'s `audit.tail` arm builds
its wire JSON by an explicit field list, and that list was never extended. Without the fix,
resolving "the record `undo_rotate` just wrote" by `(action, generation)` — the only way a
*second* `entry.undo` can find it, since `record_decision` always logs the outer call under the
literal op name (`"entry.undo"`), never the shape of what it did — had nothing to query against.
Fixed by adding `"entry": r.entry_id, "generation": r.generation` to the non-agent branch only;
the agent-redacted branch (`id`/`action`/`timestamp`/`actor`) is untouched, matching this ADR's
own Decision 3 claim that the redacted shape doesn't change.

**Test:** `crates/store/src/rotation_history.rs` (save/load round trip, wrong-root-key and
tampered-body refusal, not-found for a generation never recorded — mirrors `entry_archive.rs`'s
own test shape, 5 tests) and `crates/brokerd/tests/entry_undo.rs` (10 tests, via
`server::handle_request` so every assertion has a real audit id to work from — `ops::dispatch`
alone never writes one: undo-a-rotate restores the exact prior ciphertext and manifest metadata,
and the original `entry.rotate` record survives unmodified; undoing that undo restores the
rotated-to value in turn, proving the chain — via `undo_rotate`'s own `entry.rotate`-shaped audit
line, not the generic `entry.undo` one; undo-a-remove restores the entry, both `replace` and
`keep-both`; wrong-node id and a bogus id are both `not_found`, indistinguishably; undoing a
denied action or an `entry.create` record is `NotUndoable`; capability and lock gates match
`rotate`/`remove`) plus `credmgr_mcp::tools`'s registry test confirming `credmgr_undo` now maps
to a real op.

---

## ADR-056 · The session/login mechanism (ADR-047's named gap): a real `vault.unlock`/
`vault.gate_verify` success mints a real, global-scoped, `Origin::HumanUi` token — and the
R3-universal-Admin question (ADR-051) is answered by construction, not by changing R3

**Context.** ADR-047 traced the gap precisely: `crates/brokerd/src/scope.rs`'s `resolve_scope`
has exactly one path that can ever produce a non-`Agent` origin — an explicit token looked up in
`TokenStore` — and nothing on any real transport ever calls `TokenStore::issue`. Every
`Origin::HumanUi`/`Origin::Native`+`Capability::Admin` scope in this workspace's own tests is
built by a fixture calling `state.tokens.issue(...)` directly
(`crates/cli/tests/broker_integration.rs`'s own `Fixture::issue_token` doc: "there is no
wire-level login op yet... this is the only way any client, this fixture included, can ever
present an `Origin::HumanUi`+`Admin` token"). Two concrete things stayed unreachable as a result:
`audit.tail`'s already-built per-origin redaction (ADR-049) never sees a non-`Agent` origin
through a real socket, so its unredacted branch is provably dead code (`PHASE8_AUDIT_REPORT.md`
C-2: "Re-check this the moment ADR-047's session/login lands"); and ADR-051's own "not fixed
here" note — R3 (`target is global → ALLOW`) is unqualified by capability, so *if* a
non-global-scoped token ever held `Capability::Admin`, R3 would let it administer `global` too —
sat undecided because nothing could construct that shape outside a test fixture to test it
against.

`crates/cli/src/main.rs`'s own `call()` already names the intended shape, unbuilt: `CREDMGR_TOKEN`,
read from the environment (never a CLI flag — argv is shell history and `ps` output, the same
reasoning `10_API_AND_MCP.md §2` already applies to passphrases), is presented on every request,
with the doc comment "There is no `credmgr login` yet... this is the client-side half of whatever
Phase 5's session flow ends up writing to this env var." The client-side half already exists; this
ADR builds the half that writes to it.

**Decision — a successful full unlock *is* the login. No new authentication step.**
`vault.unlock`'s `Ok(false)` branch (no gate enrolled, unlocked immediately) and
`vault.gate_verify`'s `Ok(())` branch (gate completed) are the two places `07_TWO_FACTOR.md §3`'s
five-step sequence reaches "the operator has now proven passphrase-plus-TOTP knowledge" — that
proof is already stronger than anything else in this codebase gates `Capability::Admin` behind
(`vault.gate_enroll_begin`/`confirm`, `node.seal`/`restore`, `grant.create`'s non-presence half all
substitute "holds `Capability::Admin`" for a missing native-presence factor; a real unlock is the
one thing in Phase 3-5-so-far that is *not* a substitution). Both branches now:

1. Call `state.tokens.issue(GLOBAL_ID, ALL_CAPABILITIES, Origin::HumanUi, None)` —
   `ALL_CAPABILITIES` is every `Capability` variant (`List, Read, Reveal, Create, Update, Notes,
   Admin`); the ceiling withholds nothing from the one caller in this system who, per
   `05_THREAT_MODEL.md §5`, already "can read anything, including orphaned data" by definition of
   holding the passphrase and the TOTP.
2. `node_id: GLOBAL_ID`, not a wildcard/no-node sentinel — `BrokerScope`/`Scope` have no such
   concept, and global is the one node this token can always legitimately claim self-identity
   against (R2).
3. `Origin::HumanUi`, not `Origin::Native`. This is the deliberate, minimal reading of "something
   stronger than 'asked nicely for `Capability::Admin`'" (ADR-047's own phrase): completing a real
   unlock is that something-stronger for `HumanUi`, but `Origin::Native` additionally requires a
   live presence attestation (R0's own check: `subject.origin == Origin::Native &&
   subject.presence_attested`) that no transport through Phase 5 can supply (ADR-046) — minting
   `Native` here would be the exact "lock icon that means less than the user thinks"
   `16_CROSS_PLATFORM.md §3`/ADR-041/046 already forbid. `credmgr` (CLI, over the UDS broker
   protocol — the only real client that drives `vault.unlock` interactively today, per
   `10_API_AND_MCP.md §1`, there being no HTTP surface at all, ADR-019) is an honest `HumanUi`
   claim; it is not a `Native`-with-presence claim, and does not pretend to be one. Orphan access
   (R0) and every presence-gated positive path (`totp.seed`, `grant.create`'s non-presence half,
   `node.reparent`, `vault.approval_decide`'s notification half) stay exactly as inert as they were
   before this session — unaffected by this ADR, precisely as ADR-046/049 already anticipated.
4. `bound_workdir: None`. A login session is not "this project's" token the way a cwd-matched
   agent scope is (`06 §4`'s anomaly check exists to catch a *stolen* project-scoped token
   presented from the wrong directory); an operator who just typed their own vault passphrase is
   expected to `cd` around freely afterward, and flagging every `cd` as a `TokenWorkdirMismatch`
   anomaly would train the operator to ignore the signal that matters (`05_THREAT_MODEL.md §7`).
5. The minted id is returned in the wire response: `vault.unlock`'s `{"locked": false}` and
   `vault.gate_verify`'s `{"locked": false}` both gain a `"token"` field. No existing test asserts
   exact equality on either payload (`crates/cli/tests/broker_integration.rs`'s
   `assert_eq!(stdout.trim(), "locked: false")` is `cmd_status`/`vault.status`, an unrelated op,
   confirmed by reading it before relying on it) — adding a field is additive on the wire.
6. `BrokerState` gains `session_tokens: RwLock<HashSet<String>>`, populated by both mint sites.
   `lock()` — ADR-043's single funnel for idle timeout, explicit `vault.lock`, and
   sleep/screen-lock/session-end alike — now also drains this set and revokes every id in it via
   `self.tokens.revoke(id)`, before clearing it. A login session does not outlive the unlock it
   came from, the same "elevations are dropped on lock" discipline `07 §5` already states for gate
   2FA's own scoped elevations; re-unlocking mints a fresh token rather than resurrecting the old
   one. Every full unlock mints a *new* token unconditionally (no dedup against an
   already-active session) — simpler, and consistent with nothing else in this codebase
   deduplicating token issuance either.

**CLI wiring (the "real, non-fixture client" the exit criteria name).** `cmd_unlock` now prints,
in addition to the existing `locked: <bool>` line, `export CREDMGR_TOKEN=<id>` when the response
carries a token — capturable with `eval "$(credmgr unlock <<< "$pw")"`, the same idiom
`ssh-agent -s`/`gpg-agent` use for exactly this "a subprocess authenticated, hand the result to my
shell" shape. A new subcommand, `credmgr gate verify <code>` (`vault.gate_verify`, wired the same
way — `<code>` is a 6-digit TOTP, not a secret in the `passphrase`/`set` sense, so it is an
ordinary positional argument, not stdin), completes the two-factor path for a vault with gate 2FA
enrolled and prints the token the same way once the second factor succeeds. Neither command was
reachable from the compiled binary before this session (`vault.gate_verify` had no CLI surface at
all).

**A named, deliberate limitation, not silently discovered and left implicit.** A `GLOBAL_ID`-
scoped token — however it holds `Capability::Admin` — cannot administer, list, or audit any node
*other than* `global` itself. Every existing Admin-gated op resolves the capability against a
*specific* node (`node.seal`/`restore`/`reparent` and `grant.create`/`vault.approval_decide`
against the node in question; `node.create` against the *parent*; only `vault.gate_enroll_*` and
`maintenance.backup` resolve against `GLOBAL_ID` itself) — and per `06_ACCESS_GRAPH.md §1`, a
`global`-scoped subject reaches a specific project via none of R2 (not self), R3 (target isn't
global), R4 (wrong direction — global is the ancestor, not the descendant, of every project), R5
(opt-in `descendantRead`, off by default on every node including `global`, and turning it on
globally would flatten the entire isolation model this vault exists to enforce), R6 (depth-1
nodes are never siblings) or R7 (no grant exists to a token that was just minted) — R8 denies.
`audit.tail`'s own node-reachability filter (ADR-049, the same `resolve_capability(...,
Capability::List, ...)` per-node check `node.list`/`whoami`/`graph.snapshot` use) is bound by the
identical limit: a login session's `audit.tail` sees `global`-scoped records in full, unredacted
detail (the thing this ADR actually needed to prove reachable), not a portfolio-wide feed. This is
**exactly** the "whole vault graph" gap ADR-047 already named and explicitly left to "whichever
session wires the Tauri `apps/desktop/src-tauri` backend to `credmgrd` for real" — this session
does not solve it, and does not silently claim to. `credmgr node create <id> --parent global` (a
depth-1 project) works today with the new session token; `credmgr node seal <existing-project>`
does not, and needs its own, still-undesigned per-node elevation path — named here so the next
session opens with it instead of re-deriving it, the same courtesy every prior ADR in this file
extends forward.

**A sharp edge this same limit produces, found while testing, worth stating plainly so it isn't
rediscovered as a bug report.** `vault.unlock`'s own audit record is stamped against the
*caller's pre-unlock* scope's node (`server::record_decision`'s `params.node`-or-`scope.node_id`
fallback — `vault.unlock` sends no `params.node` of its own), which is whatever the connecting
process's cwd resolves to. An operator who runs `credmgr unlock` from inside `~/projects/acme/`
gets an unlock record stamped `node: acme` — invisible to the very `global`-scoped session token
that unlock just minted, by the identical R2/R3/R4/R5/R6/R7-all-fail reasoning above. Unlocking
from a directory with no registered node (or from the vault root) stamps it `global`, which the
session token *can* see. Nothing about this is wrong — cwd-based audit attribution is exactly
what `06 §4` specifies, and it is arguably more useful this way (the record names *where the
human actually was*) — but it means "did my own unlock show up in `credmgr audit`" depends on
where the terminal happened to be `cd`'d, which is worth knowing before it reads as a missing
record instead of an expected one.

**The R3-universal-Admin decision (ADR-051's "not fixed here"), answered: leave `resolve()`
unchanged.** ADR-051's exact question was whether R3 ("target is global → ALLOW") should stay
unqualified by capability, or be narrowed to exclude `Admin`, once a real token-issuance path
existed. Tracing every op that resolves `Capability::Admin` (above) shows R3 is not actually the
rule doing any work for the one real path this ADR builds: a `global`-scoped subject checking
`Admin` against `global` hits **R2** (self) before R3 is ever reached — R3 only matters for a
subject scoped to some *other* node holding `Capability::Admin`, and after this session, in real
(non-fixture) operation, `Capability::Admin` is reachable **only** via this mechanism, which
mints it **only** at `node_id: GLOBAL_ID`. No code path in this workspace — `capabilities_for_agent_access`
(cwd fallback, never grants `Admin`), the MCP surface (`FORBIDDEN_OPS`, no token-issuing op at
all), or this ADR's own two mint sites — can construct an `Admin`-holding token scoped to a
non-`global` node outside a test fixture. R3's admin-unqualified clause therefore stays exactly as
inert in real operation after this ADR as it was before it, for the same reason ADR-051 itself
gave for deferring the question ("not reachable through any shipped client today") — the
difference is that reason now holds *by construction*, not by absence of a mechanism. Narrowing R3
today would defend a token shape nothing in this codebase can produce, which is precisely the
"inventing that seam under time pressure... exactly the kind of unscoped addition the build's own
discipline exists to prevent" move ADR-046 already named and rejected once. **If a future session
ever mints a non-`global`-scoped `Admin` token** (a per-project delegated-admin role, say — no such
feature exists or is designed) **— that is the session that must revisit R3, not this one.**
Recorded here, explicitly, so it is a decision on the record rather than a silently-expired TODO.

**Rejected.** *A broker-layer bypass* ("if `scope.holds(Admin)`, skip `resolve_capability`" for
some or all ops) — ADR-047 already rejected exactly this shape for `graph.snapshot` specifically
because nothing could construct an `Admin`-holding scope outside a fixture; now that a real mint
path exists, the objection changes but the conclusion doesn't — a blanket capability-check bypass
would extend today's `global`-only reach into every node silently, which is the same
"whole-vault-visibility without a designed grant" shortcut already named as future, not
present, work. *A brand-new `resolve()` rule granting a `global`+`Admin` subject reach into every
node* — seriously considered (it would close the "named limitation" above in one stroke), and
rejected for now because it is not what either named blocker (`audit.tail` redaction, R3) actually
requires, it would make the *first* login session capability-equivalent to Native-with-presence in
every respect except orphan reach, and it is exactly the kind of consequential, hard-to-reverse
access-graph change `06_ACCESS_GRAPH.md` itself should gain a worked trace for before it lands —
better designed deliberately, by the session that also builds the per-node elevation UX it implies,
than folded into this one as a side effect. *A client-side session file* (`~/.credmgr/session` or
similar) — `crates/cli/src/main.rs`'s own `CREDMGR_TOKEN` doc comment already commits this
codebase to the env-var shape; a second, file-based mechanism would be two ways to do the same
thing for no benefit, and a file is one more thing `guard-no-secrets.mjs`/the `.gitignore` audit
would need to know about. *Minting the token from `handle_request`/`server.rs` instead of
`ops::dispatch`* — every other op-specific wire field (`entry.reveal`'s value, `entry.rotate`'s
generation) is added inside its own `dispatch` arm; `record_decision`'s generic id is the one
exception, and it exists precisely *because* it is generic across every op, which minting a token
is not.

**Consequence.** `audit.tail`'s redaction-by-origin branch (ADR-049) is now reachable end-to-end
through a real compiled binary talking to a real broker, closing `PHASE8_AUDIT_REPORT.md` C-2's
own "re-check the moment ADR-047's session/login lands" note — a full, unredacted `global`-scoped
audit feed is exactly what a `credmgr unlock && credmgr audit` session now produces. ADR-051's
open question has a recorded, evidenced answer instead of an indefinitely-deferred one. The
larger "operator administers any node, not just global" capability remains open, named, and
handed forward exactly as ADR-047 already handed it forward once.

**Test:** `crates/brokerd/tests/session_login.rs` — `vault.unlock` with no gate enrolled mints a
token whose id resolves (via a second, tokened request) to `node_id: global`, every capability
held, `Origin::HumanUi`; the two-step gate path mints one only after `vault.gate_verify` succeeds,
not after the first-factor `vault.unlock` alone (which still returns `two_factor_required`, no
token); `vault.lock` (and, separately, an idle-timeout `tick_autolock`) revokes every session
token minted since the last unlock — a presented, pre-lock token id is `capability_not_held`/no
longer resolves after; a login token reaches `global`'s own audit trail unredacted but a sibling
project's records do not appear for it at all (the named limitation, pinned by a test so it can
never silently regress into looking fixed); an equivalent-shaped scope built by hand with
`node_id` set to a non-`global` node and `Capability::Admin` still resolves `Admin` against
`global` via R3 exactly as before (documents current behaviour deliberately, per the R3 decision
above, rather than leaving it un-pinned) — that last case is a direct `core::access::resolve()`
unit test, since no real mint path can produce that scope to exercise via the broker.
`crates/cli/tests/broker_integration.rs` (or a new `session_cli.rs`) — `credmgr unlock` against a
real fixture broker (real passphrase over stdin, no gate enrolled) prints an `export
CREDMGR_TOKEN=` line; piping that token into a second real `credmgr` invocation's env and calling
`credmgr audit` returns unredacted records, proving the whole chain — passphrase in, token out,
token back in, unredacted audit out — through the actual compiled binary, not `ops::dispatch`
called directly.

---

## ADR-057 · The Tauri↔broker bridge holds the session token in Rust; the webview never sees it

**Context.** `apps/desktop/src-tauri` was the stock `create-tauri-app` scaffold: one
hello-world `greet` command, no knowledge that `credmgrd` exists. Every screen Phase 6 builds —
in-house; no external front-end team has ever existed or held this package, commit `ee59696`,
see `HANDOVER_STATE.md` — could therefore only be verified against mocks until this bridge
existed. Wiring the bridge raises three questions that are decisions, not implementation
details.

*First, custody.* ADR-056 makes `vault.unlock`/`vault.gate_verify` mint a real capability
token — `GLOBAL_ID`, `Origin::HumanUi`, every capability including `Admin`. Its success body
is literally `{"locked": false, "token": "cmt_…"}`. The obvious wiring returns that body to
the webview and has JS pass the token back down on each call. That would place a
`global`-scoped `Admin` credential in the one process this product otherwise keeps
credentials out of: `17_AIRLOCK_AND_LLM.md`'s A-1 gives the product no outbound network
surface at all, and a token in a JS variable hands every bug in the web layer — an injected
script, a stray `console.log`, a devtools screenshot — the full capability set.

*Second, revocation is silent.* `vault.lock` revokes every outstanding session token
(`state.rs::lock()` drains `session_tokens`), ADR-043's idle timer does the same on a
wall-clock tick with no event delivered to any client, and restarting `credmgrd` discards the
store. But the broker does not *reject* an unknown token id: `scope::resolve_scope` step 1
fails to match it and falls through to step 2, resolving the caller from its cwd as
`Origin::Agent`. A revoked token therefore **demotes** its holder rather than failing it. A UI
holding one keeps working with quietly fewer capabilities, and the damage surfaces later as
inexplicable `capability_not_held` denials on screens that worked a minute earlier.

*Third, duplication across a deliberate boundary.* ADR-035 excludes this crate from the v2
workspace so Tauri's edition-2024 tree cannot drag the security crates off their 1.78 MSRV
pin. So the bridge cannot `use credmgr_brokerd::protocol` or `credmgr_store::paths`; it needs
the wire framing, the error vocabulary and the socket path, and each must come from somewhere.

**Decision.**

1. **The token lives in Tauri managed state and is never returned to the webview.** A
   `Session` type holds `Mutex<Option<String>>`; `vault_unlock`/`vault_gate_verify` remove the
   `token` field from the response before returning it and store it, and every outbound call
   attaches it Rust-side. The commands return `{locked, authenticated}` — whether a session
   exists, never the credential that constitutes it. **This is the citable rule: no value
   derived from a session token — not the token, not a prefix, not a hash — crosses the IPC
   boundary into the webview.**
2. **`locked: true` is treated as proof the held token is dead**, from any of three places: a
   response's own `locked` field, `graph.snapshot`'s `meta.vaultLocked`, or a `vault_locked`
   denial. The bridge drops its token on each. Since nothing pushes the idle auto-lock to a
   client, an ordinary status poll is the *only* way it can be noticed, so noticing it there
   is load-bearing rather than defensive.
3. **The transport and the socket-path rule are re-implemented, not imported — and pinned by
   guards that read the real source off disk.** `tests/drift_guards.rs` parses
   `crates/brokerd/src/protocol.rs` (all 19 `"error"` discriminants must equal the bridge's
   `BROKER_ERROR_CODES`, both directions), `crates/brokerd/src/ops.rs` (every op the bridge
   sends must exist as a dispatcher arm), and `crates/store/src/paths.rs` (the
   `<vault>/run/broker.sock` rule, the `CREDMGR_VAULT_DIR` override, the four-branch platform
   table). A guard that compared the copy against itself would pass on both sides of a
   divergence; one that reads the original cannot.
4. **Broker error codes are passed through verbatim**, never translated into a friendlier
   vocabulary, so a denial rendered on screen is the same word `audit.tail` records for it.
   `two_factor_required` therefore reaches the UI as an error, because that is what it is on
   the wire; the UI branches on the code.
5. **Only the read and authentication surface is wired** — `vault.status`, `vault.unlock`,
   `vault.gate_verify`, `vault.lock`, `whoami`, `graph.snapshot`, `entry.list`,
   `entry.reveal`. Eight of 38 (40 as of 2026-09-13, after ADR-061).

**Rejected.** *A path dependency on `credmgr-store`/`credmgr-brokerd`* — correct in the
abstract, but it drags the crypto tree and the MSRV pin across exactly the boundary ADR-035
drew, to obtain four lines of path arithmetic and a list of strings. *Returning the token and
letting JS pass it back* — the standard web-app shape, and precisely wrong for a product whose
threat model assumes the local machine is shared with hostile agents. *Translating
`two_factor_required` into a success variant* — friendlier, but it puts the bridge and the
audit log into two vocabularies for one event. *Mirroring a literal in both trees and calling
the pair a guarantee* — considered and dropped: both copies can be updated together and
wrongly, and it leaves a second thing to keep in sync. *Wiring the mutating ops now* — each
carries an optimistic-concurrency `generation` and several sit behind presence or approval
gates whose UX is Phase 6 work; wiring them ahead of the screens that drive them would be
guessing at their shape.

**Consequence.**

- **A new trust boundary exists that did not before.** Until now the only clients of
  `entry.reveal` were a terminal and a test harness. Decrypted plaintext now crosses into a
  webview process. `05_THREAT_MODEL.md` has to consider that boundary explicitly; the bridge
  neither logs, caches, nor retains the value, but it does hand it to a renderer.
- **The passphrase argument is honest about being inert.** `vault.unlock` ignores it today —
  the broker's keystore is fixed at process start, and per-request passphrase wiring is Phase
  5's `PlatformKeystore` work (ADR-041). It is sent anyway, exactly as
  `crates/cli/src/main.rs::cmd_unlock` does, so the call site needs no change the day that
  lands. It arrives as a JS string already copied by the IPC layer, and Rust does not
  guarantee the heap allocation is zeroised — a real limitation, named rather than papered
  over.
- **Unix only.** `credmgrd` binds a `UnixListener`, so there is no Windows named pipe to talk
  to yet (`16_CROSS_PLATFORM.md` plans one). Non-Unix builds compile and return
  `platform_unsupported` rather than failing to build.
- Two `Cargo.lock` files remain, per ADR-035; this crate gains one dev-dependency
  (`tempfile`). 40 tests: 23 unit, 13 against a real Unix socket, 4 drift guards.
- `greet` is retained deliberately: it is stock Tauri scaffold, not an external team's output,
  and `apps/desktop/src/routes/+page.svelte` still invokes it. Remove it once Phase 6 replaces
  that scaffold and nothing calls it. *(Done 2026-10-02: ADR-075 replaced the scaffold page and
  `greet` and the `opener` plugin went with it; `src-tauri/tests/shell_config.rs` fails if either
  returns.)*

## ADR-058 · The corpus document header: YAML front matter at byte 0, the `artifact-hardened` stamp immediately after it

**Context.** Two contracts both want the top of the file. The portfolio three-pass contract
(`~/.claude/CLAUDE.md`) requires an `artifact-hardened` stamp at the top of every source-of-truth
artifact, and has always been satisfied by putting that HTML comment on line 1. `tools/docgen`
requires YAML front matter at byte 0: `classification._FRONT_MATTER_RE` is anchored with `^\s*---`
and no `MULTILINE` flag, so a comment on line 1 makes the header unparseable, `parse_header`
returns its sentinel, and every gate fails closed. A document cannot satisfy both with the stamp
first. This became live the moment the corpus started building through the pipeline; before that,
no `v2/docs/` document had front matter at all.

**Decision.** Front matter first, stamp on the line immediately after it. Both are still "at the
top of the file"; the ordering is forced by the machine-readable contract, which is the one that
cannot be flexible. The stamp keeps its exact existing syntax so `tools/corpus_check.py stamps`
and any future reader parse it unchanged. `generator._render_markdown_body` drops HTML comments
rather than escaping them, so the stamp no longer renders as visible source at the top of every
built document — which is what it did before this session.

**Also fixed here, because it is the same contract.** Every corpus document takes the id `V2-0NN`,
where `NN` is the file's own number (`00_README_START_HERE.md` → `V2-000`). The `DOC_MANIFEST.md`
row is keyed `V2` — the **prefix**, not a doc id, because `classification._extract_prefix` splits
on the final `-<digits>`. Only `id`, `variants` and `surface` are machine-checked; the manifest's
other columns are documentation.

## ADR-059 · Status vocabulary for the corpus, and the rule that a `planned` subsystem is never written in the present tense

**Context.** The operator's standing instruction is that every document be written out in full to
its ultimate destination, with unbuilt subsystems fully designed — and, asked directly, that
honesty is not traded for completeness: a document carries an honest current status *and* the
complete target spec. Without a fixed vocabulary that instruction produces the worst possible
artifact, a corpus that describes a finished system in the present tense while a third of it does
not exist. This corpus already had that defect in a mild form: `18_ENDPOINT_INDEX.md` maps V1's
routes onto a planned op surface (`agent.token_*`, `field.*`, `keystore.*`, `llm.*`,
`vault.set_passphrase` and more) that is marked `planned` nowhere, and `10_API_AND_MCP.md`
documents the Pass-1 planned surface as though it were the shipped one.

**Decision.** Three words, no synonyms, one per subsystem heading, as a bolded lead:

- **`built`** — exists in `v2/crates/**` and is covered by a passing test. Cite the file and the
  test name.
- **`partial`** — exists but does not yet do everything this document specifies. Cite what is
  missing.
- **`planned`** — does not exist in any form. Say so plainly; design it completely anyway.

**And the rule that carries the weight: a `planned` thing is never written in the present tense.**
Not "the org vault syncs over a pairing code" but "will sync" / "is designed to sync" / "the
target design is". A reader who cannot tell design from implementation cannot use the document for
either purpose, and a document that reads as though something is built when it is not is worse
than one that says nothing at all. `status:` in the front matter carries the document's own state:
`verified-current` when every claim in it was checked against source in the pass that wrote it,
`needs-verification` otherwise.

## ADR-060 · A figure's authoring artifact lives beside its document; `renders/golden/` is the engine's fixture set, not the project's figure registry

**Context.** `tools/ENGINE_ROUTING_POLICY.md` explicitly left this open ("where blueprint JSON/SVG
pairs live long-term — a per-document sibling folder vs. a central registry — provisional until a
second and third document prove it out"). The first document, `session-login-mechanism.md`, split
them: the docgen sibling spec `<stem>_spec.json` beside the document, and the visual-engine job at
`tools/visual-engine/renders/golden/SIM-03-login-funnel.job.json`, with the caption naming the
golden file as the source.

**The evidence that settles it.** Those two files were compared this session. They had already
drifted — `classification: "public"` in the document's spec, `"internal"` in the golden job — one
session after being written, by the session that wrote both. This is the third time this project
has paid for the same mechanism: the design bundle's `reference/` directory silently regressed to
a pre-sanitisation copy carrying a leak that had already been fixed in the original
(Session 20), and `18_ENDPOINT_INDEX.md` drifted from the broker for months because its only
guard was a test that did not exist. **Two copies of one fact always diverge here.**

**Decision.** The `<stem>_spec.json` beside the document is the single source of truth for that
document's figures. docgen reads it and nothing else, so anything elsewhere is by definition a
copy. A visual-engine chart embeds its job packet verbatim in that spec under `"kind": "echarts"`;
it is not also stored as a standalone job file. `tools/visual-engine/renders/golden/` keeps its
real and different job: the **engine's own** regression fixtures, which prove the engine renders
byte-identically across changes to the engine. Project figures get their determinism guarantee
from the document build instead — `tools/docgen/tests/test_generator_build.py` asserts that
building the same document twice is byte-identical, which is the property that actually matters
for a document.

**Consequence to carry out.** `session-login-mechanism.md`'s caption and §6 name the golden job as
the figure's source. That reference is now backwards and must be reversed when that document is
next touched: the spec beside it is the source, and `SIM-03-login-funnel.job.json` is the engine
fixture that happens to share its shape.

## ADR-061 · Vault bootstrap (`credmgr init`) is broker-side, two-phase, and does not extend to a live daemon's `vault.unlock`

**Context.** `PROJECT_MAP.md §5` item 21 (2026-08-29) found the actual top gap in the project:
397 tests pass and the broker is real, but no code path anywhere writes `root.wrap.pass`,
`root.wrap.recovery`, or a node key file — there is no way to create a vault. `04_CRYPTO_AND_KEYS.md
§2.3` names the target shape (generate RK, wrap three ways, display the recovery code once,
require re-entry, refuse a hardware-only finish, write registry+HMAC+counter in that order) but
not the transport or process model, because nothing in the codebase had settled it yet.

**Three things this session found that the existing docs did not resolve, each of which shapes the
design below:**

1. **`crates/cli/src/main.rs`'s own module doc is a hard invariant, not a preference:** "talks to
   `credmgrd` over the local socket/pipe; never decrypts directly... none decrypts directly" is a
   closed Phase 4 exit-gate bullet. ADR-001 generalises this to "every client is a socket peer,
   none holds a node key directly." Root-key generation and wrapping are more sensitive than
   anything the CLI process currently touches — doing them CLI-side to sidestep the missing daemon
   would violate the one invariant this whole security model is built on, for the sake of the
   single hardest feature to get right.
2. **`credmgrd`'s `main()` does nothing.** `#[allow(unused)]`-free but inert: it prints a status
   line and returns, never calling `server::run`. There is no code path in this repository, ever,
   that has run the broker as a real process outside a test harness. This is not a separate gap
   from vault bootstrap — `04_CRYPTO_AND_KEYS.md §2.3` names both in the same paragraph — and
   `credmgr init` is unusable by an actual human until it is fixed, so wiring `main()` to call
   `server::run` for real is in scope here, not a follow-up.
3. **`scope::resolve_scope` already degrades safely against an empty registry.** No token, no
   workdir match (nothing to match — the registry has no nodes yet) falls through to its own
   existing third branch: `BrokerScope { node_id: GLOBAL_ID, capabilities: [List], .. }`. A
   pre-vault `credmgrd` process needs no special "unbootstrapped mode" in `server.rs` — the
   existing resolution order already produces a minimal, harmless scope for a connection with
   nothing to authenticate against. `vault.init_begin`/`vault.init_confirm` (below) are dispatched
   under exactly this scope and gate themselves on "does a vault already exist", not on a
   capability nothing could hold yet.

**Rejected alternative: do the crypto in-process inside `credmgr` (the CLI binary).** Simpler —
no daemon-lifecycle question, no two-phase op, no `PendingInit` state. Rejected because of point 1
above: it is the one thing this codebase's own architecture doc and its own exit-gate test
(`no_secret_in_argv.rs`'s sibling invariant, "none decrypts directly") say a client must never do.
A test could pass with the root key materialising in the CLI's address space for the seconds it
takes to write three files; the invariant would still be broken in exactly the way ADR-001 exists
to prevent.

**Rejected alternative: one `vault.init` op, synchronous, no confirmation step.** The target design
explicitly requires "**setup will refuse to finish with only a hardware wrap**" and "display the
recovery code exactly once and **require the operator to re-enter it before setup completes**."
A single synchronous op cannot pause for that re-entry without either (a) blocking the whole
broker thread on interactive input it has no business reading — the broker is a daemon serving a
socket, not a terminal — or (b) writing the vault to disk before the operator has proven they
copied the recovery code down, which is the wrong side of "before setup completes" to fail on.

**Decision — two-phase op, mirroring `vault.gate_enroll_begin`/`_confirm`'s already-precedented
shape:**

- **`vault.init_begin(passphrase)`.** Refuses if `paths.registry().exists()` (a vault is already
  there) or if the resolved vault root sits inside a `.git` working tree (new check — see below).
  Otherwise: generates the root key and the `global` node's X25519 keypair; wraps the root key via
  a **throwaway** `SoftwareKeystore` built from `params.passphrase` (this session's request-scoped
  keystore, discarded after the wrap — it never becomes `state.keystore`, and `state.keystore`
  is never read by this path); generates one 256-bit recovery code
  (`credmgr_core::recovery::generate_recovery_code` — singular, not the 2FA gate's ten short
  codes; `NEXT_SESSION_PROMPT.md`'s "match that UX pattern" line was about the show-once
  mechanism, not the count, and conflated the two recovery-code mechanisms in `crates/core` —
  flagged here rather than silently "corrected" past, since a prior session's prompt is itself a
  record) and wraps the root key under it; wraps the `global` node's private key under the root
  key. Of the four secrets that exist in the clear during this step, two are gone by the time the
  function returns — the node's private key and the recovery code's own raw bytes zeroise via
  their existing `Drop`/explicit-`zeroize()` discipline (`StaticSecret`/`Zeroize`, the same
  pattern the rest of this crate already relies on) — and the passphrase is consumed into the
  throwaway keystore and never stored anywhere. **The root key is the one secret that does
  survive**, held in `PendingInit` as a `SecretBox<[u8; 32]>`: `registry_file::save`'s HMAC
  signature needs it again at `init_confirm` time, and generating a second root key there would
  not help, since the wraps already committed to the first one. This is not a new pattern —
  `PendingGateUnlock` already holds an unwrapped root key in memory across an equally-interactive
  two-step flow (factor 1 passed, waiting on factor 2), TTL-bounded and zeroised on drop the same
  way. Everything else in `PendingInit` is ciphertext, plus a SHA-256 hash of the formatted
  recovery code for the confirmation check — never the plaintext recovery code, never the node's
  private key. Returns the plaintext recovery code exactly once, the same "in the response value,
  never stored, never re-fetchable" shape `gate_enroll_confirm` already uses (`state.rs`'s own doc
  comment on that function, verbatim precedent).
- **`vault.init_confirm(recoveryCode)`.** Re-checks the vault doesn't already exist (idempotent
  under a retry), requires a live, unexpired `PendingInit` (`GATE_UNLOCK_TTL_SECONDS`-style TTL,
  reusing the existing constant rather than inventing a second unexplained window — see ADR
  precedent in `state.rs`'s own comment on `GATE_UNLOCK_TTL_SECONDS`), and compares the retyped
  code's SHA-256 hash against the one `init_begin` stored. **Plain `==` on the two 32-byte
  hashes, not a constant-time compare, and that is a considered choice, not an oversight:** this
  is a same-process, same-call-stack, no-network "did you copy this down" check on an operation
  that already succeeded cryptographically — the wrap is what protects the vault, not this
  string match — so there is no remote timing oracle for a constant-time compare to defend
  against, unlike `credmgr_core::signing::verify`'s HMAC check (which guards a real network-facing
  authentication decision and does use `hmac`'s constant-time `verify_slice` for exactly that
  reason). On match: writes `root.wrap.pass`, `root.wrap.recovery`, `keys/nodes/global.key`, then
  an empty `manifest.json` for `global` (`manifest::save` — not named in `04_CRYPTO_AND_KEYS.md
  §2.3`'s own steps, but required: `verify_and_load_vault` iterates every node the registry names
  and fails outright if any lacks one on disk, found by this ADR's own integration test actually
  driving that load path rather than only checking file existence), then `registry.json`+
  `registry.sig` (`registry_file::save`, `vaultGeneration: 1`, with `doc.manifests` recording the
  cross-binding `manifest::save` returned), then the external generation counter
  (`FileGenerationCounter`, matching `check_and_advance`'s baseline) — key material and the
  manifest before the registry that references them, registry before the counter that anchors it,
  so a crash at any point leaves either nothing or a strictly-earlier-and-still-consistent prefix.
  Also commits `wrapped_root`/`node_wrapped_keys`/`node_public_keys`/`registry` into the *running*
  `BrokerState` via a new `load_key_material`
  method (state.rs's counterpart to `verify_and_load_vault`'s plaintext-only load, which that
  function's own doc comment already flagged as deliberately not covering key material, "that
  lands with Phase 4/5's vault bootstrap" — this is that landing). Clears `PendingInit` last, so
  the root key it held zeroises only after every write that needed it has happened.
- **New CLI subcommand `credmgr init`:** resolves the target vault directory the same way
  `credmgrd` will (`CREDMGR_VAULT_DIR` or the OS default) purely to run the **new**
  git-working-tree guard client-side too, for a fast, no-broker-round-trip refusal — the
  authoritative check still lives in `init_begin`, this is a courtesy early exit, not a second
  source of truth. Reads the passphrase as one line from stdin, calls `vault.init_begin`, prints
  the recovery code with an explicit "you will not see this again" line, reads a second line from
  stdin for re-entry, calls `vault.init_confirm`. On a hash mismatch the vault is not written and
  the operator can retry `init_confirm` (still-live `PendingInit`) without regenerating the whole
  vault, or re-run `credmgr init` from scratch once the TTL lapses.
- **The V1-parity git-working-tree guard is new code, not already-structural.** `paths.rs`'s
  "never inside a repository" claim is true only because `default_vault_dir()` never reads `cwd` —
  confirmed by grep, zero references to `.git`/cwd anywhere in `crates/store` or `crates/cli`. That
  covers the *default* path. `CREDMGR_VAULT_DIR` is honoured with zero validation, so an override
  pointed at a checkout would succeed silently today — V1's `credmgr init` had an explicit second
  defense for exactly this (`v1/CHANGELOG.md` 1.9.0: "`credmgr init` refuses to create a vault
  inside a git repository, and every command warns if an existing vault is in one"). `init_begin`
  adds the explicit check V1 had and V2 never ported: walk up from the resolved vault root looking
  for a `.git` entry, refuse if found, regardless of whether the path came from the default or the
  override.
- **`credmgrd::main()` now calls `server::run`.** Resolves `VaultPaths::default_location()`,
  constructs `BrokerState::new` with a **placeholder** `SoftwareKeystore` built from an empty
  passphrase, and serves the socket. The placeholder keystore is never used by `vault.init*`
  (which always builds its own request-scoped keystore, per `init_begin` above) and is
  **known and explicitly not fixed to be usable by `vault.unlock`** — see the boundary below.

**The boundary this ADR does not cross, stated plainly so it is not mistaken for an oversight:**
`vault.unlock`'s dispatch arm already, today, ignores `params.passphrase` entirely and calls
`state.unlock()`, which unwraps against `state.keystore` — the keystore `credmgrd` was
constructed with **at process start**, before any passphrase could be known. `cmd_unlock`'s own
code comment names this exactly: "real per-request passphrase wiring belongs to Phase 5's
`PlatformKeystore` selection, ADR-041." Fixing it would mean changing `state.unlock()`'s
signature and every existing test fixture built around "the keystore already knows the right
passphrase because the fixture constructed it that way" — a second, broader redesign (which
keystore tier, not just which passphrase) that a prior session already scoped out to Phase 5
on purpose. This session does not touch it. Concretely: a real, running `credmgrd`, after a real
`credmgr init`, will **not** yet honour a real `credmgr unlock` from a separate process — that
gap is unchanged by this work, now simply visible and reachable (there was previously no vault to
even attempt it against) rather than invisible. **What this session does prove**, honestly and
exactly: the on-disk artifacts `credmgr init` produces are the ones `vault.unlock`'s *cryptography*
needs — a freshly constructed `BrokerState`, given the same passphrase and pointed at the files
`init_confirm` wrote, unwraps and unlocks correctly. The integration test proves the vault is
real; it does not, and does not claim to, prove the deferred keystore-selection wiring is fixed.

**Consequence to carry out, recorded so the next session doesn't have to re-derive it:** Phase 5's
`PlatformKeystore` selection (ADR-041) is the natural place to also resolve `vault.unlock`'s
passphrase wiring — when that work happens, `vault.unlock`'s dispatch arm should build its
keystore attempt the same request-scoped way `vault.init_begin`/this ADR does, rather than reading
a keystore fixed at `credmgrd` process start.

---

## ADR-062 · The desktop bridge reaches every broker op, ahead of the screens that will drive them

**Context.** ADR-057 wired 8 of the broker's ops into the Tauri bridge and rejected wiring the
rest "ahead of the screens that drive them", because each mutating op carries an optimistic-
concurrency `generation` and several sit behind presence or approval gates whose interaction
design belonged to the front-end track. `19_FRONTEND_DELIVERY_SCOPE.md §8` then split the
remaining work cleanly: the front-end track builds screens against mocks shaped like §4's real
responses; **this repository** supplies "the `#[tauri::command]` glue — one command function and
one test per op". Two findings on 2026-09-24 made the split concrete: the bridge's own suite
(outside `cargo test --workspace`, ADR-035) had been red for three weeks — its error-vocabulary
drift guard caught the four ADR-061 error codes and nothing ran it — and the eight wired ops
were all the desktop could reach, so every screen past login was mock-only by construction.

**Decision.** Every broker op gets a command, and the bridge makes no UX decision for any of them.
Thirty-four commands are generated from one `bridge_ops!` table in `commands.rs`; each row is the
single place its op name, its Rust argument names and its wire keys exist, and the same row emits
the `BridgedOp` metadata the drift guards read. `generation`, presence and approval semantics stay
broker-side and reach the UI as the broker's own error codes — so wiring early decides nothing a
screen later has to undo, which was ADR-057's only objection. The bridge ships a typed TypeScript
client (`apps/desktop/src/lib/bridge.ts`) as part of the same contract, owned by this side, and
held to the Rust table by a guard.

**The session-reconcile fix that full coverage forced.** `vault.node_lock` answers
`{"node", "locked": true}` about one node; the bridge read any top-level `locked: true` as "the
vault locked" and would have dropped the login the moment a user locked a single project — after
which a missing token silently demotes the caller rather than failing. `Session::reconcile_ok`
now honours a flat `locked` only on the four vault-state ops (`VAULT_STATE_OPS`) and
`meta.vaultLocked` everywhere.

**Guards (all read the other side's source off disk).** Every op `ops.rs` dispatches has a command
and every command names a real op (both directions); every key a command sends is read by that
op's arm, and every key the arm requires is sent as required — the one forward-declared exception
(`audit.get`'s `id`) is listed with its reason; every command is registered in
`generate_handler!`; `bridge.ts` invokes every command exactly once with exactly its wire keys and
its `BrokerErrorCode` union equals the broker's vocabulary. Each guard was mutation-tested: a
renamed wire key and a dropped handler line each turn it red. The suite also runs in CI now
(`security.yml` → `v2-desktop-bridge`), because the token-custody tests are security tests.

**Also here, because the same pass found it: a real CSP.** `tauri.conf.json` carried
`"csp": null` — `05_THREAT_MODEL.md`'s release gate. Production is now `default-src 'self'`, no
`unsafe-*`, no origin but Tauri's own IPC, `data:` for images only; development alone may reach
the local Vite server. `tests/shell_config.rs` reads the file and fails closed on `null`.

**Rejected.** Hand-writing the thirty-four commands (≈500 lines where the op name and the key
list would exist twice per op, which is the drift the guards exist to prevent); generating the
TypeScript from Rust (a second build system for one file — a guard against a hand-written file
catches the same drift for none of the machinery).

**Test.** `apps/desktop/src-tauri`: 64 passing, 0 failing — `tests/bridge_ops.rs` (every generated
command's frame, token attachment, optional-omission, and the 42-command no-token sweep),
`tests/drift_guards.rs`, `tests/ts_client.rs`, `tests/shell_config.rs`, and unit tests including
`session::tests::locking_one_node_is_not_mistaken_for_the_vault_locking`.

---

## ADR-063 · The live daemon opens its vault: request-scoped unlock, load-from-disk, and write-through

**Context — measured with the real binaries, not reasoned about.** On 2026-09-24, against a
throwaway vault: `credmgr init` created a vault correctly; `credmgr unlock` with the same
passphrase then answered `wrong_passphrase` — on the same daemon, and again after a restart.
Three defects, each hidden by the fact that every one of the 406 tests constructs its own
correctly-keyed `BrokerState`:

1. `vault.unlock` ignored its `passphrase` and unwrapped with the keystore `credmgrd` built **at
   process start** from an empty passphrase (ADR-061's "Consequence to carry out" named this).
2. Nothing loaded an existing vault after a restart — `credmgrd::main` deliberately skipped it,
   having no root key to verify the registry with.
3. Every mutation lived only in memory. `entry.create` wrote its ciphertext file and updated an
   in-memory manifest; `node.create`, grants and the gate never reached disk. A restart kept the
   envelopes and lost every name, node and grant that gave them meaning.

**Decision.**

- **`vault.unlock {passphrase}` is the live unlock** (`state/durable.rs`,
  `unlock_with_passphrase`). It builds a `SoftwareKeystore` from the passphrase — ADR-041's
  permanent tier, request-scoped exactly as ADR-061 prescribed — proves it against
  `keys/root.wrap.pass`, and only then: loads and verifies the vault from disk if this process
  has not (`verify_and_load_vault`: registry HMAC, the external rollback counter, every
  manifest's cross-binding; then every node's wrapped key and public key, and the persisted
  gate); consults the gate; and — once the vault is actually unlocked — keeps the **root key**
  resident until `lock()`, dropping the passphrase keystore at once (as amended below; the first
  version installed the passphrase keystore as the broker's own instead). A wrong passphrase, a tampered or rolled-back vault, or an
  unanswered gate each leave the broker holding nothing new. `vault.unlock` without a passphrase
  keeps its old behaviour against a fixture's own keystore; against the daemon's inert
  placeholder it refuses, which is the safe reading of "none sent".
- **Key custody, as amended.** While a live vault is unlocked the broker holds its root key in a
  zeroise-on-drop box and nothing else from the unlock; `reauth_root_key` reads that and, for a
  disk-backed vault, never the start-up keystore. This replaces `04 §6`'s "RK is not kept
  resident" for the live Software-tier unlock, deliberately: the Software tier's only alternative
  is keeping the *passphrase* resident, which re-derives the same key, and the first version did
  exactly that — see the amendment for what it cost.
- **Write-through.** After any op in `ops::PERSISTED_OPS` succeeds on a disk-backed vault,
  `dispatch` calls `state.persist`, which writes, in `04 §2.3`'s order (the recovery an interrupted write needs is in the amendment below): node key files,
  then a manifest for **every** registry node (including one that has never held an entry — the
  trap `confirm_init` hit for `global`, which this ADR's own test hit again for an empty node),
  then the signed registry (merging the live registry into the last-written document so
  persistence-only fields — `created`, `publicKey`, a grant's `createdAt` — are kept, not
  invented), then the external generation counter last. A crash between the last two leaves the
  registry one generation ahead, which `check_and_advance` accepts; never behind, which it
  refuses. One writer at a time (`persist_lock`). If the write fails the caller gets `internal`
  naming the op — the change is live in memory but was not saved, and saying `ok` would be a lie
  a restart exposes. An in-memory fixture is never "durable" and never writes, so every
  pre-ADR-063 test is unchanged.

**Named limits, not silently left.** The locked-write tray's metadata and the sealed-node records
`node.restore` reads are still memory-only (their ciphertext is on disk; the bookkeeping is not):
a restart forgets pending writes and in-window seals. Before the first unlock after a restart the
graph is empty — the registry cannot be verified without the root key, and an unverified registry
is never shown. `node.seal` needs an `orphan` node's public key, which `credmgr init` does not
create (the orphan cold key is `planned`, `04 §5`), so sealing is unavailable in a vault `init`
made. All three are recorded in `OPEN_WORK_REGISTER.md`.

**Rejected.** Keeping the passphrase keystore resident while unlocked (the first version's
choice — it re-derives RK on demand, so it is no narrower than a resident RK, and it made the
daemon's own keystore a way in; see the amendment); loading the vault at daemon start with an unverified registry
so the locked graph renders (shows the owner data nothing has authenticated); a separate
`vault.persist` op the client must remember to call (every forgotten call is silent data loss).

**Amendment — adversarial review, the same day.** The first version of this ADR was reviewed by an
independent adversarial pass before anything was committed. It found one critical, two high,
four medium and seven low defects; every one was fixed and each is pinned by a `review_*` test in
`crates/brokerd/tests/durable_vault.rs` that fails against the first version.

| Finding | What was wrong | Now |
|---|---|---|
| **C1** critical | The passphrase keystore became the broker's own keystore, so once the owner had unlocked, a passphrase-less `vault.unlock` from any local process unwrapped with it and minted a whole-vault login; a `lock()` racing an unlock could also leave it installed | RK resident instead (above); a passphrase-less unlock is refused on any disk-backed vault; unlock, `gate_verify`, `gate_recover` and `lock()` are serialised on one lock |
| **H1** high | A missing rollback counter read as generation 0, so deleting it let an older, validly signed registry — one from before the gate — load as current; the registry was read twice, and a FIFO could serve two different registries to the two reads | Loading reads each file once and commits nothing until everything verifies; a missing counter is refused (override: `CREDMGR_ACCEPT_MISSING_ROLLBACK_COUNTER=1` for a vault moved between machines); `atomic::read` refuses symlinks and FIFOs |
| **H2** high | Not crash-safe: manifests are written before the registry that binds them, and `registry.json`/`registry.sig` are two writes — a crash between any two left a vault that would not open; `node.create` inserted the node before fetching the key it needed, so a failure there left a keyless node every later write failed on | Everything is computed before the first write; `registry_file::save` keeps the previous verified pair, recovered only if it is not older than the counter; a manifest exactly one generation ahead of its binding (authenticated under RK) is accepted as the interrupted-write case; `node.create` keys the node before registering it |
| **M1** medium | Audit records re-derived RK per request — a 256 MiB Argon2id for anyone, locked or not | A locked disk-backed vault answers `reauth_root_key` at once; an unlocked one reads the resident key |
| **M2** medium | A locked `entry.create` (the pending tray) succeeded and then reported `internal`, because write-through could not run locked | Write-through is skipped while locked (the tray is not persisted — K-7) |
| **M3** medium | Re-enrolling a confirmed gate needed no current second factor, and the gate is now durable | See ADR-064's amendment |
| **M4** medium | `maintenance.doctor` wrote the registry outside the persist lock; a second daemon could steal the socket; the counter was not monotonic | Doctor writes under the lock and refreshes the persisted view; `persist` numbers past both its own view and the counter, and the counter only moves forward; `server::run` refuses a live socket |
| **L1–L7** low | Load not all-or-nothing; replay ledger survived only as a maximum; entry refs restarted each start; workdirs parsed before authorisation and `$HOME` accepted; a staged re-enrolment and the gate seed lingered; an owner login never idled out while agents were busy; `gate_recover`'s timing showed which factor failed | All fixed — L2 and L6 in ADR-064/065's amendments |

**Honest bound that remains (K-8).** In the Software tier the rollback counter is a file in a
directory the same OS user can write. An attacker who holds the passphrase *and* can restore both
an older vault registry and the matching older counter file can roll the vault back — including
to before a gate was enrolled. Deleting the counter no longer works; restoring a matched pair
still does. Hardware tiers (N3) close this with a hardware monotonic counter. Recorded in
`PHASE8_AUDIT_REPORT.md §4`.

**Test.** `crates/brokerd/tests/durable_vault.rs` — the `review_*` regressions above, and: init→unlock on the same broker; restart→unlock
loads from disk; wrong passphrase loads nothing; nodes and entries survive a restart and decrypt
with reloaded keys; a tampered registry and a validly-signed-but-older registry are each refused
at unlock; locking drops the ability to write. End to end with the real `credmgrd` and `credmgr`
binaries: init → unlock → `set` → restart → unlock → `get` returns the value; a wrong passphrase is
refused; the plaintext appears in no file under the vault directory.

---

## ADR-064 · The vault gate is persisted, re-enrolment cannot silently remove it, and the last door exists

**Context.** Gate enrolment (`07_TWO_FACTOR.md §3–4`) lived only in `BrokerState.gate`. Once
ADR-063 made the vault survive a restart, that became a security defect rather than an
inconvenience: an operator enrols 2FA, the daemon restarts, and the vault silently unlocks on the
passphrase alone. Two further gaps sat next to it: `gate_enroll_begin` on an already-confirmed gate
**replaced** it at once, so a re-enrolment started and abandoned left the vault ungated; and
`07 §4`'s "last door" — passphrase **plus** the root recovery code re-enrol a lost gate — was
unbuilt, which is Phase 5's sixth exit-gate line (`12_BUILD_PLAN.md §2.6`).

**Decision.**

- **Persist the confirmed gate in the registry's `gate.twofa`** (on the scope's own node —
  `global` for the vault gate): `{ v: 1, confirmed, secret, recoveryHashes, lastCounter }`. The TOTP
  secret is sealed with ChaCha20-Poly1305 under `HKDF(RK, "credmgr/v2/gate-secret/<scope>")`
  (`credmgr_core::keys::seal_under_root`), so reading the registry does not reveal the seed; the
  registry's HMAC is what stops anyone without RK from stripping or altering a gate. Recovery codes
  stay the SHA-256 hashes the broker already held (`null` once burned). `lastCounter` is re-entered
  into the replay ledger at load, so a TOTP step accepted before a restart is refused after it.
  An unreadable gate document is a hard load failure, never "no gate" — silently dropping one
  would turn corruption into a 2FA bypass.
- **A re-enrolment over a confirmed gate is staged** (`gate_pending`) and replaces the gate only
  when confirmed with a code from the new secret; until then the old gate, and its recovery codes,
  stay in force.
- **`vault.gate_recover {passphrase, recoveryCode}` — the last door.** Both factors must
  independently open the *same* root key — the passphrase through `root.wrap.pass`, the printed root
  recovery code through `root.wrap.recovery` — compared in constant time. On success it removes
  the gate (and any staged re-enrolment and parked unlock) and writes the vault through; it does
  **not** unlock. The operator then unlocks on the passphrase and enrols a new gate. A wrong pair
  is `wrong_passphrase`, never saying which factor failed. No capability check — the caller is
  locked out by definition, and the two factors are the authorisation — but the op shares
  `vault.unlock`'s per-uid auth backoff in `server.rs`. Not an MCP tool (a policy change,
  `10 §3.2`). CLI: `credmgr gate recover`, with `credmgr gate enroll` added alongside it (`07 §4`
  named the missing CLI enrolment path).

**Rejected.** Storing the gate secret in the clear inside the signed registry (integrity without
confidentiality — anyone with read access to the vault directory learns the seed); a recovery that
also unlocks (turns a re-enrolment path into a bypass, the very thing `07 §4` says it is not);
answering which factor failed (a free oracle).

**Amendment — adversarial review, the same day.** Two changes. **Replacing a gate that is in force
now needs its second factor, fresh** (review M3): `vault.gate_enroll_begin`/`_confirm` over a
confirmed gate answer `two_factor_required` unless the elevation window a successful
`vault.gate_verify` opens (`07 §5`, five minutes by default) is live. Without it, anything holding
the owner's login — an exported token (K-6) — could swap in an authenticator of its own, and since
the gate is now durable the swap would outlive the session. A first enrolment has no gate to
prove and needs nothing extra. **The replay rule survives a restart as a floor** (review L2): the
last accepted step is re-entered on load as a minimum, and any step at or below it is refused —
the first version kept only the maximum in the ledger, so a lower step inside the ±1 skew window
could be accepted once after a restart.

**Test.** `crates/brokerd/tests/durable_vault.rs` — an enrolled gate survives a restart and still
gates; a TOTP step accepted before a restart is refused after it; a burned recovery code stays
burned; an abandoned re-enrolment leaves the gate in force; the gate seed appears in no file under
the vault directory in base32, hex or raw form; and
`the_last_door_passphrase_plus_root_recovery_code_re_enrols_the_gate_after_device_loss` — gated and
factor-less after a restart, either factor alone refused, both together reset (and leave the vault
locked), the passphrase alone then unlocks, a new gate enrols and gates across the next restart.

**Amendment (wiring audit Q-2, 2026-11-21) · the last door refuses an agent.** The wiring audit
(`research/2026-11-20/WIRING_AND_ISOLATION_AUDIT.md`, Q-2) found that `vault.gate_recover` and
`vault.recover` — both token-less last doors — treated agents differently: ADR-163 item 7 refuses an
agent before any code is read, while this op tried the factors for any caller (a cwd agent got
`wrong_passphrase`). "No capability check" above still holds for a person; the op now also refuses,
with `capability_not_held` (`admin`), a caller the broker identifies as an agent (an agent token, or no
token from inside a registered project folder; `BrokerState::is_identified_agent`), **before either
factor is read**, and asks again inside `gate_recover_scope` once a freshly started broker has loaded the
registry (`GateRecoverError::Agent`, the same second asking as ADR-163's review P1-1). An agent holding
both secrets had already won, so the risk was low; the asymmetry is gone and the rule is one rule. The
refusal counts in neither direction of the auth backoff. `node.gate_remove`'s factor path, which also calls
`gate_recover_scope`, needs the owner's login already and is unchanged. Tests:
`crates/brokerd/tests/recover_unlock.rs::the_gates_last_door_refuses_an_agent_before_either_factor_is_read`
(an agent session, right and wrong factors, the gate still in force) and
`::the_gates_last_door_refuses_an_agent_in_a_registered_project_folder_loaded_or_freshly_started` (the real
request path on a loaded and a freshly started broker — mutation-checked: without the second asking the
fresh broker resets the gate — then a person's terminal resets it with the same factors);
`scripts/endpoint-matrix.py` (`agent:acme` with both right factors, `capability_not_held`).

---

## ADR-065 · A real login reaches its owner's whole vault — every node but Orphaned

**Context.** ADR-047 named the gap and left it to "whichever session wires the Tauri
`apps/desktop/src-tauri` backend to `credmgrd` for real": *the native app cannot show its owner
their whole vault graph until some mechanism issues it a token whose reachability set is "the whole
tree," established at real unlock time.* ADR-056 built the login but kept it `global`-scoped, and
recorded the consequence as a named limitation: `global` cannot read its children (R8), so a
logged-in owner could not list, read or write a single project. With ADR-062's bridge complete,
that limit became the whole desktop product: every graph, list and inspector would have shown
`global` alone.

**Decision.** A **real login session** — a token minted by `vault.unlock`/`vault.gate_verify` and
still registered in `session_tokens` (`lock()` revokes and forgets every one) — is evaluated **as the
target node itself** (`ops::subject_for`). `resolve()`'s precedence does the rest: R0 (Orphaned:
native + live presence only) and R1 (a locked vault or node blocks reveal/update) come before R2,
so both still bind the owner exactly as they bind anyone. Nothing else widens: an agent's scope, a
cwd-derived scope, and any scope that merely *claims* `Origin::HumanUi` without a registered token
resolve exactly as before. `crates/core::access` is unchanged — this is a broker-side choice of
subject, not a new rule.

**Why this is the owner, not a shortcut.** `05_THREAT_MODEL.md §5` already states that the
passphrase holder "can read anything, including orphaned data"; the login is minted only after
the strongest authentication the system has (passphrase, plus the gate when enrolled). ADR-047's
own objection was to a scope that is *claimed* ("asked nicely for Admin"); `is_owner_session`
requires the token id the unlock itself registered.

**The known risk this creates, named with its bound (K-6).** `credmgr unlock` prints the token as
`export CREDMGR_TOKEN=…` for `eval` (ADR-056). Exported into a shell where an AI agent also runs,
it now hands that agent every project, not only `global`. Bound: it dies at lock — explicit, idle
(15 min, ADR-043), sleep or restart; it never reaches Orphaned; the desktop bridge never exposes it
(ADR-057); and — since the review amendment below — it is revoked after the idle timeout of its
*own* inactivity, even while agent traffic keeps the vault unlocked. Mitigation shipped: the CLI
prints a warning line with the token. Owner: operator.
Resolution path: a per-shell, cwd-bound owner token or a desktop-only owner flag, decided by the
operator if the CLI export pattern is kept.

**Rejected.** Turning on R5 (`descendantRead`) on `global` (would give every *agent* the same
reach, which is what isolation exists to prevent); a new `access::Rule` (the same effect with a
change to the pure core and its matrix, for no added safety).

**Amendment — adversarial review, the same day (L6).** The first version bounded K-6 by "it dies
at idle lock", but the vault's idle clock counts every request, so an agent polling the broker
kept an unused owner login alive indefinitely. A live login now has its own idle clock
(`session_last_used`, refreshed only by requests that present it) and `tick_autolock` revokes it
after the vault idle timeout even while the vault itself stays unlocked for agents (ADR-043
unchanged).

**Test.** `durable_vault.rs::the_owner_session_reaches_every_project_but_an_agent_and_a_fixture_claim_do_not`
— the owner's `whoami` reaches `global`, `acme`, `globex`; an agent scoped to `acme` is still denied
`globex`; a HumanUi scope without a minted token is denied; `lock()` ends the reach.

---

## ADR-066 · Directories can be bound to a node

**Context.** `03_DATA_MODEL.md §1` gives every node `workdirs` — absolute, canonicalised,
globally unique directories that scope an agent launched inside one to that node (`scope.rs`,
`06 §4`). Nothing could ever set them: `node.create` hard-coded `workdirs: Vec::new()` and no op
edited a node's list, so in a vault `credmgr init` made, no agent could ever be scoped to a project.

**Decision.** `node.create` takes an optional `workdirs`, and a new `node.set_workdirs {node,
workdirs}` replaces a node's list (`[]` clears). Paths must be absolute and existing directories;
the broker stores them **canonical** (`/tmp/x` → `/private/tmp/x` on macOS) because it matches them
against the kernel's own resolved cwd of the calling process (`peer.rs`) — an uncanonical path would
never match. `/` is refused — and, since the review (L4), the home directory and every ancestor of
it, since binding one would scope every agent the user launches. Uniqueness across nodes is
enforced by `validate_registry`, where the
invariant already lived. Human-only: it needs `Capability::Admin` on the node, which no agent scope
holds (`capabilities_for_agent_access`), and it refuses `Origin::Agent` outright besides — re-pointing
a directory re-points every agent launched in it. Written through (ADR-063). CLI:
`credmgr node create … --workdir <dir>` and `credmgr node workdir <id> [<dir>…]`, resolving a
relative argument against the caller's own cwd.

**Test.** `durable_vault.rs::a_bound_workdir_scopes_an_agent_to_its_project_and_survives_a_restart`
— stored canonical; relative, missing and root paths refused; one directory cannot be bound to two
nodes; an agent cannot re-bind; after a restart a process inside the directory resolves to the
node as `Origin::Agent`, and one outside it to `global`'s list-only fallback.


## ADR-067 · A manifest entry's `sha256` digests its sealed envelope, not its plaintext

**Context.** `03_DATA_MODEL.md §8` recorded an open item: `entry.create`, `entry.update` and
`entry.rotate` each wrote `sha256_hex(value.as_bytes())` — the SHA-256 of the **plaintext** — into
the unencrypted manifest, and nothing ever compared it to anything. That is an offline oracle: with
read access to the vault directory, a guessable value (a PIN, a short passphrase) is confirmed by
hashing candidates, skipping Argon2id and every key entirely. `03 §8` declined to fix it as a doc
edit — changing what a shipped field means is a code change with a decision behind it. The
Session 27 review raised it again as gap G-12 (2026-09-24).

**Decision.** The field keeps its name and place and now holds the SHA-256 of the **sealed
envelope** — the exact bytes written to `entries/<id>.env` (or `pending/<id>.env` while locked),
computed in all three ops from the value `envelope::seal` returns. It is still a change detector,
it reveals nothing the envelope file beside it does not, and it becomes what `03 §8` said it was
for: checkable **without a key**, by hashing the file on disk. Restore and undo copy the field
from the snapshot they restore, as before.

**Verification — built the same day.** `maintenance.verify` now hashes each `entries/<id>.env`
and compares it with the manifest's digest (`credmgr_store::verify::find_digest_mismatches`),
reporting a mismatch as an error — the file on disk is not the one the signed manifest describes:
tampered, corrupted, or left by an update interrupted between its envelope and its manifest.
Tests: `maintenance.rs::verify_flags_an_envelope_whose_bytes_do_not_match_its_manifest_digest`,
and `maintenance.verify` answering clean on a real vault after create, update, rotate and a tray
accept (`durable_vault.rs`). No migration: before ADR-063 (the same
release) the real daemon persisted no manifest, so no vault it wrote carries a plaintext digest;
a fixture-built vault from an earlier test run would, and is not a user vault.

**Test.** `crates/brokerd/tests/durable_vault.rs::g12_no_file_in_the_vault_carries_a_digest_of_a_stored_value`
— creates and rotates entries holding guessable values, then walks every file under the vault
directory and asserts neither value's plaintext digest appears anywhere.

## ADR-068 · A token the broker does not hold is refused, not resolved from the caller's cwd

**Context.** `06_ACCESS_GRAPH.md §4` step 1 — "explicit token, its nodeId wins" — said nothing about
a token the broker does not recognise, and `scope::resolve_scope` simply fell through to step 2,
resolving the caller from its cwd as `Origin::Agent`. A revoked login therefore produced no error:
it silently *demoted* its holder, and failures surfaced later as unexplained `capability_not_held`
or `not_found` on requests that had worked a minute before. The desktop bridge worked around it by
treating any vault-level `locked: true` as proof its token was dead. ADR-065's review amendment (L6)
then opened the one case that workaround cannot see: a login unused for the idle timeout is revoked
on its own clock **while agents keep the vault unlocked**, so no lock signal ever arrives. Found by
the 2026-09-24 corpus sweep (`19 §3.2`, `05 §3.4`).

**Decision.** `server::handle_request_at` refuses a request that presents a token `resolve_scope`
did not find with a new error, **`session_expired`** ("this login is no longer valid — it idled out,
the vault locked, or it never existed — unlock again"). `resolve_scope` itself is unchanged; the
refusal sits where the request's own `token` field and the resolved scope are both in view. Seven
ops are exempt, because a dead token must never stand between its holder and reporting state,
logging in again, bootstrapping or locking: `vault.status`, `vault.unlock`, `vault.gate_verify`,
`vault.gate_recover`, `vault.init_begin`, `vault.init_confirm`, `vault.lock`
(`server::TOKENLESS_OK_OPS`). A request that presents **no** token resolves exactly as before — cwd
scoping for agents and the MCP server (which never sends one) is untouched. The bridge adds
`session_expired` to `SESSION_ENDED_CODES`, so it drops its token on it as on `vault_locked`; the CLI
prints the broker's message. The broker's error vocabulary is now 24 codes.

**Rejected.** Reusing `vault_locked` — the bridge would already have handled it, but it would be a
false statement about the vault whenever agents are keeping it unlocked. Rejecting unknown tokens
inside `resolve_scope` — its `(scope, anomaly)` contract is pure and exhaustively unit-tested, and
the exemptions are a property of ops, which it does not see.

**Test.** `crates/brokerd/tests/durable_vault.rs::an_idled_out_login_is_refused_as_session_expired_while_the_vault_stays_unlocked`;
`session_login.rs::locking_the_vault_revokes_every_session_token_minted_since_the_last_unlock`
(which until this ADR asserted the silent fallback — strengthened, not weakened: a revoked token is
now refused, the exempt ops still answer, and a tokenless request still resolves);
`session_login.rs::a_token_the_broker_never_issued_is_refused_not_resolved_from_cwd`; the bridge's
`bridge_wire.rs::an_idled_out_login_is_refused_and_the_session_dropped`.


## ADR-069 · The locked-write tray survives a restart; seal records still do not

**Context.** K-7 (`PHASE8_AUDIT_REPORT.md §4`) named three pieces of memory-only bookkeeping left
after ADR-063: the locked-write tray's metadata, the sealed-node records `node.restore` reads, and
the `orphan` node, which `credmgr init` does not create. The tray is the one a user meets in
ordinary use — an agent writes while the vault is locked, the daemon restarts, and the envelope
stays on disk while the tray forgets it ever arrived.

**Decision.** A locked `entry.create` writes `nodes/<id>/pending/<entry>.meta.json` beside the
envelope — `{v: 1, name, type, sensitivity, fieldCount, created}` — after the envelope, so a
sidecar never names a value that is not there. At the first unlock after a restart, once every
signed file has verified, the tray is rebuilt from `pending/` (`state/tray.rs`). Accept and discard
remove both files. The sidecar is deliberately **not** under the registry's HMAC: a locked write
happens with no root key resident, so nothing could sign it — and the tray is untrusted input by
design (F-1: anyone the node admits may deposit; only a human's `vault.pending_accept` takes
anything out). So the loader treats every tray file as untrusted: the digest is recomputed from the
envelope bytes (ADR-067), never read; the entry id must match what `new_entry_id` mints; the
sidecar is `deny_unknown_fields` and versioned; symlinks and non-regular files are refused
(`atomic::read`); an id already in the manifest is ignored. Anything that does not check out is
**skipped and left on disk, never allowed to fail the unlock** — otherwise one file dropped into
`pending/` would lock the owner out of their vault.

**What is not changed.** Seal records and the orphan node stay memory-only / absent: both wait on
the orphan cold key (`04 §5`), which is `planned`, and `node.seal` is unavailable in a vault
`init` made until it exists. K-7 is narrowed to those, not closed.

**Closed by ADR-079.** The orphan cold key, the orphan node at init and the seal records now exist, and
`node.seal` works in a vault `credmgr init` made — the paragraph above is the state of the record on the
day it was written.

**Test.** `durable_vault.rs::a_locked_write_survives_a_restart_and_can_still_be_accepted`
(deposit while locked → restart → the tray lists it → accept → reveal → the files are gone →
`maintenance.verify` clean → after another restart the entry is in the manifest and the tray is
empty); `…::a_hostile_or_broken_tray_file_never_blocks_the_unlock_and_never_reaches_the_tray` (an
envelope with no sidecar, a non-JSON sidecar, one with an unknown field, a foreign id and a
symlink — the unlock succeeds and only the real write comes back; mutation-checked: removing the id
check or `deny_unknown_fields` fails it); `state::tray::tests`.


## ADR-070 · Unlock backoff is capped at one hour, not fifteen minutes

**Context.** ADR-044 set the shared auth-failure backoff at 5 failures → 30 s, doubling, capped at
15 minutes (`07_TWO_FACTOR.md §5`). The operator's crypto-hardening specification, recorded
2026-09-07 in the Claude Design project's `BACKEND_HANDOFF_NOTES.md`, asks for V1's pattern: the
same start and doubling, **capped at 1 hour**.

**Decision.** `auth_backoff.rs` doubles past 8 minutes — 16 m, 32 m — and caps at 1 h. Everything
else in ADR-044 stands: keyed by uid, one counter shared by `vault.unlock`, `vault.gate_verify` and
`vault.gate_recover`, reset by a success. This supersedes only ADR-044's cap.

**Bound.** A process running as the owner's own user can keep the owner locked out for up to an
hour by failing unlocks — the socket already refuses every other uid, and such a process can do
worse. The recovery code path shares the counter by design (ADR-064).

**Test.** `auth_backoff.rs::schedule_matches_07_5_exactly` — 30 s, 1 m, 2 m, 4 m, 8 m, 16 m, 32 m,
then 1 h for every later failure.

## ADR-071 · A node can be renamed, and its policy changed by partial patch

**Context.** `06_ACCESS_GRAPH.md §10.1` designed a single `node.policy` operation; no op read or
wrote any of the six policy fields, and no op could rename a node. The Claude Design project's
handoff lists both as P1 (`node.update` / `node.policy`): its Rename, and Add-Node's advanced
options, were collected and discarded for want of an op.

**Decision.** Two human-only ops, gated like `node.set_workdirs` (never `Origin::Agent`;
`Capability::Admin` as a ceiling; `resolve` for `admin` against the node):

- **`node.update {node, label}`** — renames. The id never changes, so grants, workdirs, manifests
  and every agent's scope are untouched. Label: trimmed, 1–120 characters, no control characters.
  Orphan cannot be renamed, and neither can Global — singular and unrenamable
  (`22_ORG_VAULT_SYNC_AND_LICENSING.md` §1).
- **`node.policy {node, reason, policy}`** — a partial patch of `siblingVisibility`,
  `descendantRead`, `requireTwoFactor`, `lockAfterSeconds` (`null` clears), `privateNames`,
  `agentAccess`; unknown fields are refused, an empty patch is refused, `reason` is mandatory
  (≤ 500 characters) and is written into the audit record's `detail`. **Turning on
  `descendantRead`, or making children share (`siblingVisibility: shared`), widens reach and needs
  presence** (§10.1, the same effect as re-parenting, §6a); presence is not attestable on any
  transport yet, so such a patch answers `presence_required` and **nothing in it is applied**. The
  other fields — tightening or neutral — need only the admin gate. A policy change drops every
  gate elevation (`07 §5`). The response carries `notEnforced: ["requireTwoFactor",
  "privateNames"]`: both are stored and reported, and nothing yet acts on them.

Both are written through (ADR-063) and both are on the MCP forbidden list.

**Test.** `durable_vault.rs::node_update_renames_a_node_and_the_label_survives_a_restart`,
`…::node_policy_tightens_at_once_refuses_a_widening_without_presence_and_records_why`; the
bridge's `bridge_ops.rs` frames.

## ADR-072 · A node's note: sealed, capability-gated, bound to its manifest digest

**Context.** `03_DATA_MODEL.md §4` designed one markdown note per node; the path
(`nodes/<id>/notes.env`) and the manifest slot (`notesSha256`) were reserved and nothing read or
wrote them. The design's inspector Notes section is fully mocked for want of the ops.

**Decision.** **`notes.read {node}`** and **`notes.write {node, markdown, generation}`**, exactly as
`03 §4` specifies: the note (`{markdown, modified}` as JSON) is sealed under the node key in the
entry envelope format with the reserved envelope id `notes` — never an entry id, so a note and an
entry cannot be swapped, and the node id in the AAD keeps a note in its node. Both need the
**`notes` capability, which `read` never implies**, resolved against the node. `notesSha256` is the
digest of the **ciphertext** (ADR-067's rule), and `notes.read` refuses a file that does not match
it — an older note restored over the current one is not served. Writes need the node unlocked,
take the manifest `generation` for optimistic concurrency (F-9), are capped at 64 KiB, and an empty
`markdown` removes the note. `maintenance.verify` checks the note file against its digest with no
key. Sealing a node moves its note into the archive with the rest of the node folder.

**Test.** `durable_vault.rs::a_note_is_sealed_capability_gated_digest_bound_and_survives_a_restart`;
`store::verify::tests::a_note_is_checked_against_its_manifest_digest_without_a_key`.

**Amended (ADR-174, 2026-11-20).** Notes are no longer human-only for *reading*. An agent may read its own node's note through MCP (`credmgr_notes_read` → `notes.read`) under its own `read` capability: the node must be the agent's own (any other is refused, with nothing said of it), **agent note reads follow the high-sensitivity reveal rules (ADR-156 treats a note as High):** a **Guarded or Strict** (stored `sealed`) node keeps its note from an agent because a high value's reveal waits for the owner there and a note has no approval path (none was built), so only an **Open** node hands it over; the node's second factor is asked as for a reveal (`requireTwoFactor` `reveal`, or a node's own gate), not the weaker read-level check; a `privateNames` node answers `nameHidden`. An agent is not asked to confirm (ADR-150/156 confirmations stay a person's). The tool labels the note untrusted user content (prompt injection). **Writing stays human-only:** `notes.write` still needs the `notes` capability, which no agent scope carries, and no MCP tool maps to it (I-13). Test: `crates/brokerd/tests/adr174_notes.rs` (7), `crates/mcp/tests/i13_tool_registry.rs::agents_read_notes_through_mcp_but_never_write_them`.

## ADR-073 · `entry.create_batch` — many single-value entries in one call

**Context.** The handoff lists `entry.create_batch` as P1, for `.env` import and a many-entry
paste. `08_FIELD_MODEL.md §4` designs it around multi-field entries, which the store does not
have: every entry holds one value today (ADR-013's field model is `planned`).

**Decision.** Build the single-value form now: **`entry.create_batch {node, entries: [{name, value,
label?}]}`**, 1–500 entries. Everything checkable is checked before the first write — the `create`
gate, every name non-empty, no name twice in the batch, none already on the node or in its pending
tray — so a refused batch writes nothing. Each item is then created by `entry.create` itself, so
sealing, the locked-write tray (a locked vault holds the whole batch for review) and the envelope
digest are shared, not re-implemented. A failure part-way (a full disk) stops the batch and answers
**success** with `complete: false`, the created list and the failing item, so what was created is
written through rather than stranded. The batch is one audit record. The request shape extends
without breaking to `fields: [...]` when multi-field entries exist.

**Test.** `durable_vault.rs::entry_create_batch_validates_everything_first_and_writes_through`.

**Extended (ADR-078).** The items now take `fields: [...]` (or the old `value`/`label`), `entryType` and
`sensitivity`; every item is still validated and encoded before the first write, each document within
16 MiB and the batch within 64 MiB. The sentence above that says every entry "holds one value today" was
true when it was written and is not any longer.

## ADR-074 · MIT for everything and everyone; money is donations plus an optional commercial licence

**Context.** From 2026-08-08 to 2026-10-01 the repository carried two licences at once. `v1/LICENSE` and
`v2/LICENSE` were MIT (and `[workspace.package]` says `license = "MIT"`), while the repository
root carried a "Personal & Commercial Use License 1.0" (commit `41f961d`, 2026-08-08) that
required an organisation to buy a licence. The design corpus was written against the second:
`22 §1` records the operator's requirement that the organisation vault "only opens after the
payment is accepted", with a licence number derived from the amount paid; `22 §4.4` designed an
Ed25519 scheme to enforce it; `POST_LAUNCH_ROADMAP.md §1`–`§2` planned a payment flow, a
key-issuance system and a three-tier price list; `v2/DONATE.md` meanwhile said there was no paid
tier. A repository cannot be both, and a credential manager is the one product whose users read
the licence before they run it. The operator settled it on 2026-10-01 (commit `3ba7f77` made the
root `LICENSE` MIT).

**Decision.** Four rules, in this order of precedence.

1. **The licence is MIT, for everything and everyone, organisations included.** One licence text
   (`LICENSE`, `v1/LICENSE`, `v2/LICENSE` are byte-identical). No seat limit, no time limit, no
   licence key, no per-organisation fee, no machine binding. The MIT licence covers the source
   code; the **CredMgr** and **FreexStudio** names and marks stay governed by `TRADEMARKS.md`.
2. **Nothing in the software is gated by payment.** No feature, mode, node count, organisation
   feature, build or update depends on a licence, a payment, a donation or a key. The software
   behaves identically with or without any of them. Lite/Pro (ADR-031, `09_UI_UX_SPEC.md §5`) is,
   as before, a free and instantly reversible control-surface mode.
3. **Money comes from two voluntary places.** *Donations* (`DONATE.md`, `.github/FUNDING.yml`):
   they buy nothing and grant no licence, support or priority. And an **optional commercial
   licence** for organisations whose procurement needs a paid agreement — an invoice, a written
   licence certificate, priority support — arranged through freexstudio.com. It is paperwork and
   service, **never a condition of use**: an organisation that never buys one is using CredMgr
   lawfully and completely.
4. **What is released under MIT stays MIT.** Every version already published under MIT remains
   MIT for everyone who received it. The copyright holder keeps the right to license *later*
   versions differently; MIT permits that, and this ADR does not waive it.

**Consequences for the design corpus.**

- `22 §4.4` is rewritten. The Ed25519 payment-derived licence number, the tier encoding, and
  "a licence gates organisation features" are **withdrawn**. What survives is a single optional
  artefact: a commercial-licence **certificate** that a procurement team can verify offline. If it
  is ever signed, the primitive remains Ed25519 for the reason `22 §4.4` gave (an HMAC verifier is
  also a forger), the private key stays off every build machine, and the shipped product verifies
  only. The certificate gates nothing, so nothing in the application depends on it and no phase
  is blocked on it.
- Phase 12 (`12 §5.4`) keeps hierarchy, sync and retention; its licensing item shrinks to the
  optional certificate. Phase 11 (release signing) still needs a signature primitive; the
  certificate would be a later, optional consumer of it, not a reason to choose one.
- `05 §9.4`'s threat statement stands as an upper bound (a licence check must never become a path
  into the vault and must never use the network), and loses its commercial-enforcement clause:
  there is no term to enforce.
- `POST_LAUNCH_ROADMAP.md §1`–`§2` and `POST_LAUNCH_BLUEPRINT_PROMPT.md §2.1`/`§2.2` (payment
  flow, licence-key issuance, price tiers) are **superseded**. Dated records that describe the
  retired licence are annotated, not rewritten.
- `DONATE.md` no longer says "no paid tier"; it says nothing is paid-for-access, and names the
  optional commercial licence as a separate thing from a donation.

**Rejected.**

- *Keep the payment-gated organisation licence.* A licence check in a vault that, by A-1, makes
  no network call cannot be revoked, cannot be metered and cannot detect forgery (`22 §4.4`'s own
  analysis); in code anyone may read and rebuild, any check is one patch from gone. It would have
  charged honest organisations and nobody else, in a product whose trust case is "nothing
  surprising happens".
- *A source-available or dual licence (a business-source or non-commercial licence).* It would
  keep the code readable but make CredMgr un-forkable, un-packageable for distributions and
  unusable as a dependency — the opposite of the audience's need for a tool they can verify and
  rebuild (`TRADEMARKS.md`: free code, protected name).
- *MIT code plus features that need a key.* This is open-core in all but name, and `22 §4.4`
  had already refused it for the one place it was proposed (the Lite/Pro toggle).

**Cost.** No mandatory revenue. The project is funded by voluntary donations and by whoever buys
the optional agreement; the maintainer accepts that.

**Test.** A document check, not a code test: `python3 -m tools.corpus_check` is clean, and a grep
of the owned documentation for a requirement that an organisation must pay, or for a licence other
than MIT, finds only annotated historical records. `diff` of `LICENSE`, `v1/LICENSE` and
`v2/LICENSE` is empty; `v2/Cargo.toml` carries `license = "MIT"`.


## ADR-075 · The desktop app is the design, precompiled, under the strict CSP

**Context.** The finished app design exists as a Claude Design project and was exported as a single
`.dc.html` file. Its loader (`support.js`) fetches React 18.3.1 from a CDN, parses the template in the
browser, compiles the logic class with `new Function`, builds a `<style>` element for its hover rules
and, for `.jsx` imports, loads Babel. Every one of those is refused by the production policy
(`script-src 'self'; style-src 'self'`, no `unsafe-eval`, no `unsafe-inline`, no remote origin), which
ADR-035 and `src-tauri/tests/shell_config.rs` hold fixed. The export also cannot be committed byte for
byte: it contains private-key armour lines used as mock data (the secret gate refuses them), a
contactable e-mail address on a real brand domain and the maintainer's real project names as mock
nodes (the personal-data gate refuses them, and a project name is not something a public repository
should carry), and, in a file the app does not need, a routable server address.

**Decision.**

1. **The app is the design, precompiled.** `scripts/dc/compile.mjs` (parse5) turns the design's
   template into an ES module of `React.createElement` calls at build time; the design's logic class
   becomes an ES module; React 19.3.0 comes from npm and is bundled by Vite 8; the helmet `<style>` and
   the five `style-hover` rules become CSS files; fonts and CSS are local. A clean-room host
   (`src/dc/runtime.ts`, about 200 lines) replaces the loader. `npm run build` ends with
   `scripts/dc/verify-build.mjs`, which fails on an inline script or style, a `style=` or `on*=`
   attribute, `eval`, `new Function`, Babel, a CDN host, `insertRule`, any URL string outside a short
   allow-list, `url(data:)`, a source map, a missing font and — for a release build — the
   `window.__cm` test handle.
2. **The production CSP is unchanged.** `scripts/verify-csp.mjs` loads the built app in WebKit and
   Chromium under the policy it reads from `tauri.conf.json`, drives every dialog, overlay and
   settings section, and fails on any violation, console error or off-origin request. Three canaries
   (an injected inline style, an inline script, a remote stylesheet) must be detected, so the gate is
   shown able to fail. `connect-src` is the Tauri IPC alone; the window makes no network request and
   `cargo tree` shows no HTTP client in the shell.
3. **The upstream export is kept as a sanitised snapshot** in `v2/apps/desktop/design-upstream/<date>/`
   beside `design-upstream/PROVENANCE.md` (sha256 and size of every exported file, the stripped and
   sanitised hashes of the app file, the transform, what was not imported and why). Only what the
   build needs is committed: the app file, two CSS files, ten OFL fonts. `scripts/dc/import.mjs` is a
   fixed, re-runnable transform (strip serving-injected editor blocks, rename private-key armour
   lines, move contactable e-mail addresses to `example.com`, replace the design's paid-licence
   sentence with the MIT statement, blank the value of its hard-coded supporter code, and replace
   project names from a table that is deliberately **not** in the repository —
   `DC_SANITIZE_MAP_FILE`). **The importer fails closed:** it computes every output before writing
   any, and exits 1 with nothing written when no name table is supplied (unless `--no-name-map` is
   passed on purpose, which is then recorded in the provenance summary). The verbatim export stays in
   the Claude Design project. The design runtime (`support.js`, `image-slot.js`, `doc-page.js`) and the
   design side's dev tools are not redistributed: they carry no licence grant for an MIT repository.
4. **`src/design/` is a derived fork, edited by hand**, split into `screens/*.html` (compile-time
   `<sc-include>`) and `logic/*.js` (one prototype mixin per screen area) so that wiring work touches
   disjoint files. `design-upstream/<date>/extracted/` is the three-way-merge base for the next
   upstream drop (`git merge-file`). The upstream design is never "re-imported over" the fork.
5. **One deliberate runtime deviation.** The host passes the previous logic state to
   `componentDidUpdate(prevProps, prevState)`; the upstream host passes only props, so the design's "a
   dialog just opened" check was always true and typing in a dialog's second field threw focus back to
   the first (measured in WebKit and Chromium; `PROVENANCE.md`, "the upstream `componentDidUpdate`
   defect"). `verify-csp.mjs` runs the check on every build.
6. **Deliberate design changes**, recorded in `PROVENANCE.md`: no donation toast and no supporter
   unlock code (cosmetics are free; donating is one static entry under About, never a banner,
   countdown or gated feature — ADR-074); About → Licences states the MIT licence; local-storage keys
   that could name a vault object are hashed (`hid(kind, id)`, 16 hex characters of a domain-separated
   SHA-256); and the beta.1 scope cut — the Agents/LLM section, machine lock, duress code, security
   levels, content search, `--age` export, Destroy orphans, and the merge, re-key, export, import and
   purge operation rows — is removed from the app rather than shown as a mock. **One deviation from an
   earlier decision is recorded here, not hidden:** ADR-022 chose the vendored `force-graph@1` for the
   in-app graph; the design draws its own canvas graph (`src/design/logic/graph.js`) and the app loads
   no copy of that engine. `design/graph-engine/` still carries the engine and
   `VAULT_GRAPH_SPEC.md`; whether to adopt the engine or retire it is open.
7. **Two gates compare the fork with the upstream** while the app's write paths (and any run without
   a Tauri shell) still use the design's in-memory demo vault: `scripts/verify-parity.mjs` (52 states, in WebKit and Chromium: the 29 the
   fork did not change render the identical DOM; the 23 deliberately changed ones are each listed in
   `EXPECTED_CHANGES` with a reason and pinned to a fingerprint in `parity-fingerprints.json`) and
   `scripts/verify-design-audit.mjs` (the design team's own probe: 0 dead, 0 unlabelled, 0 clipped,
   0 squashed, 0 low-contrast controls). Both need a local copy of the export (`DESIGN_EXPORT_DIR`),
   skip loudly without one, and retire as the wiring replaces the demo data.
8. **One model, one seam.** Every read of vault data goes through `src/vault/` (`VaultModel`); the
   logic class reads only `this.vault`, never the broker. Revealed values live in a private store the
   rendered view never holds. Every rejection goes through `routeError`. All broker access is
   `src/lib/bridge.ts`, from `src/vault/` and nowhere else. In the 2.0.0-beta.1 work in progress,
   **boot, unlock with the second factor, lock and every read (the graph, the grants, each node's
   entries, the review tray, reveal) are wired to the broker; no write is, and the design's local
   write paths change only the on-screen view** (the demo vault is used only when there is no Tauri
   shell at all), and the app's README says so in its first paragraph.

   > **Update 2026-10-03 (this item described the tree on the day it was decided; it is kept as written).** The
   > wiring then completed: every screen reads from the broker and every change goes to it (call, then re-read — no
   > optimistic write), a control with no operation behind it was removed rather than left mocked, and a release build
   > carries no demo data. The in-memory demo vault named in item 7 now exists only for development and test builds and is dropped from
   > release bundles; `docs/RELEASE_VERIFICATION.md` is the human pass over what the specs cannot see. See
   > `docs/19_FRONTEND_DELIVERY_SCOPE.md`.

**Consequences.** The window needs no `unsafe-*` and no network. The snapshot is not byte-identical to
the export, which `PROVENANCE.md` states and reproduces. React 19 replaces 18.3.1 because the parity
gate is green. The fork can drift from the design project; the merge base and the `import`/`extract`
procedure bound that cost. **Known weaknesses, stated rather than softened:** the personal-data and
secret gates cannot see a project name, so the name table (kept outside the repository) is the only
control on that class, and `--no-name-map` is an explicit way around it; until the wiring lands no
write reaches the broker (`apps/desktop/README.md` says so in its first paragraph); the bundled fonts'
SIL OFL texts travel with the source tree (`third_party/fonts/`) but are not yet copied into the built
`.app`, and About → Licences does not yet name the fonts. *(An earlier draft of this record listed two
more weaknesses: an importer that only warned when the name table was absent, and an error boundary
that sat in the component that renders and so could not catch its own exception. Both were fixed
before this iteration closed: the importer now refuses, and the boundary mounts above the host in
`src/main.ts` and shows "Something went wrong" instead of a blank window.)*

**Rejected.** *Ship the loader and relax the CSP to `unsafe-eval` and a CDN origin*: it removes the one
property that makes a webview that renders secrets defensible (ADR-035). *Rebuild the screens in
Svelte by hand* (the stack the scaffold and `02 §6`/`09` were written for): it would discard a finished
design for a second implementation that has to be kept in step with it forever. *Vendor the upstream
runtime*: no licence grant for an MIT repository, and the part this app needs is about 200 lines.

**Cost.** A compiler to maintain, a fork to merge, and two gates that depend on a local copy of the
export.

**Test.** `npm run build` (the static gate), `npm run test:csp` (the release build under the production
CSP in both engines; an error-boundary panel counts as a failure), `npm test` (compiler semantics and
refusals, the importer's refusals, the model, the error router and the bridge mapping, every name the
template reads exists in `renderVals()` in each of 52 states, local-storage keys are hashed, and the
fixture broker answers in exactly the shapes `bridge.ts` declares — `tests/unit/*.test.ts`),
`npm run test:e2e` (Playwright specs against that fixture broker, each ending with 0 CSP violations,
0 console errors and 0 external requests; `screens.spec.ts` walks every screen and names any that
lands on the error screen), `npm run test:parity`, `npm run test:design`;
`src-tauri/tests/shell_config.rs` still pins the CSP shape.

## ADR-076 · `maintenance.rotate_root` — replacing the root key, crash-safely

**Context.** `04 §6` listed "Rotate root key" as **`planned`**: "new RK; all node keys re-wrapped; all
three root wraps rewritten; recovery code reissued — unlock + 2FA + presence". The app's
Advanced → "Rotate root key" control was mocked only because the op did not exist. A rotation touches a
dozen or more files in two directories (the vault, and the state directory that holds the rollback
counter), and a filesystem offers no transaction across them: replacing them one by one and dying in
the middle leaves some under the old key and some under the new — a vault that opens with **neither**.

**Decision.** Build `BrokerState::rotate_root` and the `maintenance.rotate_root` op around one
invariant: *at every instant, and after a crash at any instant, the vault opens with the old root key
or the new one, never neither.* The mechanism is a journal with a single commit point
(`credmgr_store::rotation`):

1. **Stage.** Every replacement file is written atomically and fsynced under
   `<vault>/rotation-pending/{vault,state}/…`. No live file is touched. A crash here leaves a stale
   stage and an untouched vault (old root).
2. **Commit.** The whole staged tree is fsynced, then one atomic write of `rotation-pending/COMMIT` —
   the ordered list of files with the SHA-256 of each. **This write is the point of no return**:
   before it, the old root; after it, the new. If the call reports an error after the record landed (a
   directory fsync that failed), the record on disk decides, and the rotation retries that fsync
   (`rotation::make_commit_durable`). Only when the record is proven durable does the roll-forward
   start; if the retry fails too, **no live file is moved** — the rotation switches memory, locks the
   broker and answers `completionPending: true`, and the next unlock's recovery finishes the move. (A
   power loss could otherwise keep some moved files and lose the record that says to finish.)
3. **Roll forward.** *First check, then move.* Every staged file is checked against its recorded digest
   before the first rename; a staged copy that is gone is accepted as "already moved" only if its live
   twin exists carrying exactly the committed digest. Anything else fails closed before any file has
   moved, so a torn, tampered or lost stage leaves the vault wholly in its old state instead of
   half-applied. Then each file is renamed over its live twin (both directories fsynced; digest re-read
   just before each rename; a cross-device move falls back to an atomic write then a remove). The move
   is idempotent. When the last file is in place the commit record is removed, then the stage.
4. **Recovery is key-free, runs before anything reads a root wrap, and runs under the per-vault lock.**
   `rotation::recover` only renames files. It runs at `credmgrd` start-up, at the top of
   `unlock_with_passphrase` and at the top of `gate_recover`, always through
   `BrokerState::recover_interrupted_rotation_at`. A stage with no commit record is deleted; a
   committed one is finished. A stage with no record is **not** proof that the rotation never
   committed — a rotation that finished and was cut off before removing its directory leaves the same
   thing, with the new key already in force — so the type is `Recovery::DiscardedStage` and nothing
   claims to know which.

**What is replaced — a closed, enumerated set** (`ROOT_BOUND_ARTEFACTS`, held to account by a
whole-vault before/after file diff that fails on any file nobody classified):

| # | Artefact | Bound by |
|---|---|---|
| 1 | `keys/root.wrap.pass` | Argon2id(passphrase) wrap of the new RK |
| 2 | `keys/root.wrap.recovery` | wrap under a **new** recovery code; the old code stops opening anything |
| 3 | `keys/nodes/<id>.key` | `node-wrap/<id>` — re-wrapped; each node's keypair is unchanged, so no envelope is re-encrypted |
| 4 | `registry.json`, `registry.sig`, `registry.json.prev`, `registry.sig.prev` | `registry-hmac`; the gate seeds are sealed under RK inside it (`gate-secret/<scope>`), so a gate survives and still gates the next unlock |
| 5 | `nodes/<id>/manifest.json` | `manifest-hmac/<id>`, re-bound in the registry |
| 6 | `<state dir>/vaultGeneration.counter` | `generation-counter/<name>`; outside the vault, so staged in its own base |
| 7 | `audit/<yyyy-mm>.tip` | `audit-tip/<ym>`, only if the whole month verifies under the old RK |
| 8 | `archive/<id>/meta.json` | `archive-meta/<id>` |
| 9 | `archive/<id>/node.key` | `node-wrap/<id>` — so `node.restore` still opens it |
| 10 | `archive/<id>/node/manifest.json` | `manifest-hmac/<id>` |
| 11 | `archive/removed-entries/<node>/<entry>/removed.json` | removed-entry HMAC |
| 12 | `archive/entry-history/<node>/<entry>/<generation>.json` | entry-history HMAC |

Not replaced, byte for byte: entry envelopes, notes and pending-tray items (sealed to node *public*
keys), the audit logs themselves (a hash chain; only each month's tip is signed), archived envelope
copies. **Fail closed on the unknown:** if `keys/` holds any file this build cannot re-wrap
(`root.wrap.se`, K-7's `cold/orphan.key`, whatever a later build adds) the rotation is refused with
nothing changed — a rotation that strands a key cannot be undone. **Fail honest on the unverifiable:**
an artefact that does not verify under the old root (a tampered or truncated audit month) is left
exactly as it is and named in `notResigned`; the rotation does not re-sign it, so it keeps failing
`maintenance.verify` for as long as nothing is appended to it. Appending to a month signs its tip over
the log as it stands (`audit::append` has always done this, for every request, and does not verify
first), so the month the rotation's own record lands in verifies again under the new key, truncation
and all; its `notResigned` reason says so. That is existing audit behaviour, recorded rather than
changed here (hardening it needs its own decision: how `append` should treat a tip that lags the log by
one line after a crash, or a month signed under another key).

**Authorisation.** `Capability::Admin` on `global`, human origin only — **absent** from the MCP tool
registry (on `FORBIDDEN_OPS`; I-13), not merely gated. When a vault gate is enrolled the second factor
must be fresh (`two_factor_required`, `scope: "global"`). Then **presence** (`04 §6`, `07 §5`): no
transport can attest it (ADR-047), so the wire answers **`presence_required`** after every check that
can be made without it — the `node.reparent` / `maintenance.doctor --rebuild-registry` precedent. The
rotation logic sits behind that wall in `BrokerState::rotate_root` + `ops::rotate_root_response` and is
tested directly. The day presence exists, the final `Err` in the dispatch arm becomes
`return rotate_root_response(...)`.

**Parameters and response.** `{passphrase}` — factor one **again**: the passphrase is never resident,
it is proven first against the wrap being replaced (so a typo can never become the new wrap) and is
what the new `root.wrap.pass` is made from. The op is on the per-uid auth backoff, because it answers
`wrong_passphrase`. Response: `{rotated: true, recoveryCode, nodesRewrapped, vaultGeneration,
filesReplaced, artifactsResigned, completionPending, notResigned: [{kind, id, reason}]}`.
`recoveryCode` is the new root recovery code, **shown once**, and the only secret in the response.
`completionPending: true` means the rotation committed (new key and new code already live) but moving
the files did not finish — a move failed part-way, or the commit record could not be proven durable
and nothing was moved. The broker has locked itself, the outcome is returned anyway, and the next
unlock finishes the move. A pending answer also carries `meta.vaultLocked: true`, which the bridge's
`Session` already reconciles on every op, so it drops the login the broker just revoked instead of
waiting for the next call to fail with `vault_locked`. There is no top-level `locked` key, and a clean
rotation carries no `meta`.

**Concurrency.** *Between processes*, one exclusive advisory `flock` per vault, on
`<vault>/run/rotation.lock` (an empty 0600 file; the lock belongs to the open file description, so two
broker states in one process exclude each other as two processes do, and the kernel frees it when its
holder dies). A rotation takes it for its whole duration (waiting up to 2 s, then refusing with
"nothing was changed"); every recovery takes it (waiting up to 30 s). Without it, a second `credmgrd`
that started while the first was staging read the half-written stage as a crash's and deleted it; the
first rotation then committed a record naming files that no longer existed and rolled forward over a
vault whose registry and node keys stayed under the old root while `root.wrap.pass` moved to the new
one — a vault that opens with neither. As a second line of defence a vanished staged file is no longer
read as "moved" unless its live twin carries the committed digest. `credmgrd` also skips recovery
entirely when a live broker already answers on the socket (Review M4). *Within the process*, every
request holds `request_barrier` shared for its whole life, the audit record it writes included;
`maintenance.rotate_root` is upgraded to exclusive only when the uid is not backed off, the token is
not dead, and the caller is a live owner session — a token-less peer, a stale token or a locked-out uid
is refused while sharing the barrier, so it cannot drain in-flight requests. Under the exclusive
barrier nothing can be signed under the old key between the plan and the switch, and the rotation's own
audit record (`maintenance.root_rotated`, counts only) is the first thing signed under the new one. The
rotation also holds `auth_lock` and `persist_lock`, drops every elevation and parked unlock (a
second-factor elevation is spent by a rotation, `07 §5`), and switches memory only after the commit.

**Consequences, stated rather than softened.**

- After the commit there is **no going back**: the old wraps are not retained, because a rotation that
  kept them "for rollback" would leave exactly what it is meant to retire on the disk.
- It retires the old key for the **future**. A backup, a Time Machine copy or any copy of the vault
  made *before* the rotation still opens with the old passphrase wrap and the old recovery code; the old
  file blocks are replaced by rename, not securely erased.
- If the process dies after the commit and before the response is delivered, the new recovery code was
  never seen. The passphrase still opens the vault. What `credmgrd` announces at start-up is narrower
  than that: it says so only for a crash during the roll-forward ("finished an interrupted root-key
  rotation (N files)"), and for leftover staging it says "removed leftover staging files… rotate again
  if you never saw the new recovery code", which does not claim to know whether the rotation had
  finished. A crash after the roll-forward completed (the audit append, the socket write) leaves
  nothing on disk, so start-up prints nothing; the operator's evidence is the missing response. Rotating
  again issues a code the operator holds.
- `scripts/emergency-decrypt.mjs` notices a vault caught mid roll-forward (`rotation-pending/COMMIT`).
  It reads through the staged files (the new root's vault) first, then the live files as they stand,
  writes a note to stderr, and if neither opens it says what to do — use the **new** recovery code,
  unlock or start `credmgrd` once to finish the rotation, or rotate again — instead of "authentication
  failed". Ordinary vaults keep the old messages.
- `crates/core` stays pure: it gains only `keys::rewrap_node_key(old, new, node_id, wrapped)`, which
  unwraps and re-wraps in one call. `crates/brokerd/src/state/rotate/vault_lock.rs` carries a second
  scoped `#![allow(unsafe_code)]` (beside `peer.rs`) for the `flock(2)` and `O_NOFOLLOW` calls —
  `File::lock` is Rust 1.89 and the MSRV is 1.78. On a non-Unix target the lock is a no-op stub; the
  broker does not build there, and the Windows transport must replace it with `LockFileEx`.
- Two live brokers over one vault remain unsupported (Review M4). The lock makes recovery and rotation
  safe against each other; it does not make a second broker's unlock safe against a rotation that
  starts after that unlock's recovery step.

**Spec deviations.** `04 §6` says "all three root wraps"; two exist (passphrase, recovery) — the
hardware-keystore wrap does not (`04 §2.1`) and a rotation refuses to run past one if it appears. The
spec's gate is "unlock + 2FA + presence"; the passphrase is additionally re-entered (see above).
Presence is enforced as a refusal, not an attestation (ADR-047).

**Rejected.** *Rewrite the files in place, one at a time*: every ordering has a crash point that opens
with neither key (the control test above reproduces it). *Keep the old wraps "for rollback"*: it would
leave on the disk exactly what a rotation is meant to retire.

**Cost.** One lock file, a staging tree on the same filesystem, and a recovery step on every unlock.

**Test.** `crates/brokerd/tests/rotate_root.rs` (36 tests, one of which is the helper process the
cross-process lock test re-executes): file-by-file proof that each artefact opens with the new key and
not the old; restart-after-rotate; rotating twice; a crash sweep at every staging point, before the
commit, with a commit that reports failure after the record landed, with a commit that is never proven
durable, immediately after the commit, and after each file of the roll-forward — each followed by a
fresh broker unlocking with the passphrase and reading every entry; a control showing a half-applied
state opens with neither key until recovery runs (`without_recovery_a_half_applied_rotation_opens_with_neither_key`),
so the sweep is shown able to fail; two broker states, and two real `credmgrd` processes, with the
rotation frozen mid-staging (the second waits, the stage survives); the lock bypassed as a control (the
stage is deleted but nothing is half-applied and recovery fails closed); the lock itself (in-process,
across processes, a killed holder, a symlink refused); a pending completion telling the bridge; the
barrier not taken by an unauthorised caller; start-up messages for a finished-rotation leftover; the
tampered current audit month and its caveat; daemon start-up recovery; the offline emergency script
opening the rotated vault with the new code only; no key material in clear text (byte and hex scan of
the vault and state directory for both root keys, a node private key, the passphrase and both codes);
the wire gate; the whole-vault file-diff classification. `crates/store/src/rotation.rs` unit tests (21);
`crates/core/src/keys.rs` (2); `crates/cli/tests/emergency_decrypt.rs` (7, four of them for the
rotation cases: committed but unmoved, mid roll-forward, all moved but the record remains, and a
finished rotation);
`crates/mcp/tests/i13_tool_registry.rs::rotate_root_is_on_the_forbidden_list_and_no_tool_maps_to_it`;
`apps/desktop/src-tauri/tests/bridge_ops.rs::maintenance_rotate_root_sends_the_passphrase_and_passes_the_recovery_code_through`.

### ADR-076 amendment · a rotation also replaces every project key and the sealed-copies key (2026-11-20; ADR-174)

**What changed.** The operator's decisions of 2026-11-20 (ADR-174 items 7 and 8, closing ADR-165's N5-Q1 and N5-Q2): "Rotating the root key also replaces every project key", and "Sealed copies of removed projects are re-sealed to a new key on re-key". `maintenance.rotate_root` now runs `rotate_root_locked` with `NodeKeys::Replace`, the path a passphrase change and a recovery already took (ADR-165 fourth addendum): every live node (global included, and a node locked on its own) gets a fresh X25519 keypair, and everything it holds (entries, the note, the merge memory, retained history, removed entries in their window, the locked-write tray) is opened with the old private half and sealed to the new public half, each one more staged file under the rotation's one `COMMIT` record. The orphan node's cold keypair is replaced in the same commit **even when it holds sealed copies**: each copy is opened with the old cold key and sealed to the new one (`BrokerState::plan_orphan_reseal`), the orphan manifest takes the new digests and one generation bump, and the registry names the new orphan public key. Only the machine-lock bind's own rotation still re-wraps without replacing (`NodeKeys::Rewrap`), because the bind re-keys every node right after it.

**What this amends above.** Row 3 of the table: a live node's `keys/nodes/<id>.key` is now a new keypair's private key wrapped under the new root; a sealed node's archived key is still re-wrapped (it keeps its keypair until restored; `node.rekey` gives it a new one after). The orphan cold key is a new keypair, its private half sealed under the new root. "Not replaced, byte for byte" no longer holds for entry envelopes, notes, tray items or the orphan's sealed copies: they are re-sealed. What stays byte-identical is the audit logs (only each month's tip is signed) and a sealed node's archived envelopes. The whole-vault file-diff test (`exactly_the_root_bound_files_change_and_every_file_is_accounted_for`) now requires the live nodes' envelopes, their history and removed-entry envelopes, and the orphan's copies to change (`resealed:` kinds, kept apart from the 13 root-bound kinds `ROOT_BOUND_ARTEFACTS` lists), and still requires a sealed node's archived envelopes to be identical. "Consequences": a copy of the vault from before a rotation, opened with the passphrase (which a rotation does not change) or the old recovery code, still opens what it held, but no longer anything written after the rotation, and its old cold key opens none of the sealed copies after it.

**Crash safety is unchanged in kind.** One stage, one record, the key-free roll-forward before anything reads the vault; a crash before the record leaves every file old (old root, old node keys, old cold key), after it every file new once the next unlock finishes the move. Proven by `crates/brokerd/tests/adr174_rekey.rs` (every staging cut, before the commit, right after it and every roll-forward cut, with the node keys and the orphan's copies checked at each) and by the unchanged crash sweeps in `rotate_root.rs`.

**Wire.** `maintenance.rotate_root` now also answers `nodesRekeyed` (the re-keyed node ids, sorted) and `filesResealed` (a count, the orphan's re-sealed copies included), as `vault.set_passphrase` and `vault.recover` do. The audit record says "N node keys replaced, M files re-sealed". No new op, error code or MCP tool. **Cost:** the rotation is now O(entries + history + removed + tray + sealed copies), as ADR-165 N5 measured for a passphrase change (about 7.6 s for 300 entries in a debug build).

## ADR-077 · The audit log never holds a bearer; a locked node has its own code; list, status and notes say more; a stored TOTP seed needs 80 bits

**Context.** Four things surfaced in the endpoint-matrix lane and the front-end architect's pass
(2026-10-02).

1. *The audit actor was the caller's token.* `server.rs::record_decision` and `record_anomaly` wrote
   `scope.token_id` as the audit record's `actor`, and the token-workdir anomaly's `detail`
   interpolated it as well. A token id is the bearer secret (`TokenStore::get(presented)` is the whole
   authentication). The audit log is plaintext on disk (`audit/YYYY-MM.log`) and `audit.tail` serves
   `actor` to any caller holding `list` — including the redacted agent shape and an unscoped process
   whose cwd matches no workdir. Measured on the real daemon: such a process read the owner's live
   token out of the feed, replayed it, got `whoami` = global with all seven capabilities, revealed a
   sibling project's secret (bypassing R8) and created a node. It was also a second route by which the
   bridge's "the token never crosses into the webview" rule (`19 §3.2`) could be broken.
2. *MX-1.* `totp.code` on a stored seed under 128 bits panicked the connection thread (`Totp::new`'s
   `expect`), leaving the client with a closed socket.
3. *G3.* A locked node on an unlocked vault answered `vault_locked`, which the desktop bridge treats as
   "the login is over".
4. *G1 / G2.* `entry.list` carried no manifest metadata, `vault.status` could not say "no vault exists
   yet", and a grantee holding `notes` but not `list` could not write a note from the CLI (the write
   needs the manifest generation, which only `entry.list` returned).

**Decision.**

1. **A session is named in the audit log by a public id, never by its bearer.** `Token` gains
   `public_id` — `s_` plus 16 hex digits, an independent CSPRNG draw (not a hash or truncation of the
   bearer, so nothing about the bearer is recoverable; it authenticates nothing: presenting it answers
   `session_expired`). The audit `actor` is `<Origin>:<public id>` (for example `HumanUi:s_9f3a…`) for a
   caller with a live session and just `<Origin>` for one without; it is computed once per request,
   before dispatch (`vault.lock` revokes tokens during the request that locks). The anomaly record uses
   the same actor, and its detail reads "session <public id> bound to …, presenting process cwd is …".
   Broker-internal writers keep `system:<op>`.
2. **Defence in depth, not the fix.** `token::redact_bearer_tokens` (anything shaped `cmt_` + at least
   eight hex digits becomes `[redacted-token]`) is applied to every audit `actor` and `detail` on the
   way into the log (`server.rs::scrubbed`, so a token pasted into a `reason` or a future call site
   cannot reach the file) and to `actor`/`detail` on the way out of `audit.tail` (so records written by
   a leaking build are never served). Existing lines are **not** rewritten: that would break the hash
   chain and the signed tip. `Debug` for `Token`, `BrokerScope`, `Request` and the bridge's `Session`
   prints `<bearer, redacted>` or `authenticated: bool` instead of the secret.
3. **`totp.code` cannot panic, and a stored seed needs at least 80 bits.** `Totp::try_new` is the
   checked constructor: digits 6–8, period ≥ 1, secret ≥ `MIN_TOTP_SECRET_LEN` = 10 bytes (80 bits); a
   refused secret is zeroised. It validates, then builds the wrapped engine through its
   `new_unchecked`, so the engine's own stricter check can never refuse or panic on a value `try_new`
   accepted; `verify` uses saturating arithmetic so a timestamp or period near `u64::MAX` cannot
   overflow-panic. `from_stored_secret` goes through `try_new`; `Totp::new` stays for callers that
   guarantee validity (the gate, whose secret this crate generates at 160 bits) and is documented as
   panicking otherwise. The one other place that rebuilt a `Totp` from stored bytes — loading a
   persisted gate secret in `state/durable.rs` — now uses `try_new` too and reports a corrupt gate
   document instead of panicking. A stored value that is not usable is a *typed refusal*:
   `malformed_request` whose message says why — "not a base32 TOTP seed", or the seed's length in bits
   and the 80-bit floor — and never the value. `decode_gate_secret_base32` accepts lower case,
   spaces or dashes, and `=` padding. As a safety net `server.rs::guard_against_panic` wraps
   `ops::dispatch` in `catch_unwind`: a panic inside any op is answered as a typed `internal` and
   audited like any denial, with the panic still written to the daemon log. (The general hazard is
   unchanged: std locks poison, and the `expect("… poisoned")` sites then panic on every later use;
   `guard_against_panic` changes what the caller is told, not what the state allows.)
   **A recorded deviation from RFC 4226 §4 (requirement R6),** which says a shared secret MUST be at
   least 128 bits (and RECOMMENDS 160). The RFC floor protects the strength of a secret *the verifier
   chose*; a stored seed is the opposite case — some other service chose it, issued it to the user and
   is the party that verifies the codes. This vault is the prover; it cannot make that seed stronger,
   and refusing to use it only locks the user out of a code their own authenticator app would show.
   Many real services still issue 80-bit seeds (16 base32 characters, the original authenticator key
   format), so a 128-bit floor made "store my seed, get my code" fail for ordinary accounts. Every
   secret this crate *generates* (the 2FA gate's) stays 160 bits; the lower floor applies only to the
   decode of a stored seed. Below 80 bits stays refused: no real service issues less, so such a value
   is a truncated paste or a typo, and a code derived from it would never match. Derivation is
   unchanged (the RFC 6238 Appendix B SHA-1 vector is a unit test).
4. **`node_locked`.** A new wire error, `node_locked` (`{error, node, message, remedy}`), for "the
   vault is unlocked but this node is locked individually" (`vault.node_lock`, `06 §1a`). `vault_locked`
   is reserved for the whole vault being locked. One helper, `ops.rs::locked_refusal`, decides which; it
   is the answer for `entry.update`, `entry.rotate`, `entry.remove`, `entry.restore`, `entry.undo`,
   `vault.pending_accept`, `vault.pending_discard`, `notes.read`, `notes.write` and `node.seal`. The
   error vocabulary is now **25** codes. The bridge lists `node_locked` in `BROKER_ERROR_CODES` and in
   `bridge.ts`'s `BrokerErrorCode`, and deliberately does **not** add it to `SESSION_ENDED_CODES`.
   Unchanged and recorded: `entry.reveal` on a locked node by an owner session still follows the
   approval-on-demand path (ADR-042) and answers `approval_pending`, and `totp.code` answers
   `node_access_denied` (rule R1); `node_locked` is their answer only in the narrow case where access
   is allowed but the node key is not resident.
5. **Additive fields — `entry.list` metadata is for human sessions only.** `entry.list` returns
   `entries: [{id, name, type, sensitivity, fieldCount, modified, rotatedAt, expiresAt}]` beside
   `ids`/`names`/`generation`, from the very list `ids`/`names` come from (list gate, then
   `narrow_entries`), carrying only fields the plaintext manifest holds; `rotatedAt`/`expiresAt` are
   `null` when absent. **For 2.0.0-beta.1 the `entries` key is returned only to a non-agent session
   (`Origin::HumanUi`, `Cli`, `Native`) — the same predicate `audit.tail` uses for its redacted shape.
   An `Origin::Agent` caller — the MCP surface, every tokenless cwd-scoped process, any explicitly
   issued agent token — gets exactly the response it had before this ADR (`node`, `ids`, `names`,
   `generation`); the key is absent, not empty or null.** Reason: `06 §3` lists "types, counts" among
   what the `list` capability may show, but the agent-facing surface (`credmgr_list`) has only ever
   returned ids and names, and exposing type, sensitivity, rotation and expiry dates to an agent is a
   policy decision nobody has made; this ADR deliberately narrows the agent shape to what it was until
   that is decided. The desktop bridge's sessions are always human, so it always receives `entries`. `vault.status` returns `initialized: bool`
   (`is_durable() || registry file exists`; false while an init is only pending), and the bridge's
   `AuthState` gains `initialized` (default `true` when the field is absent, so the app never offers to
   create a vault over one that exists).
6. **`notes.read` returns the manifest `generation`.** `notes.write` takes the same optimistic-concurrency
   `generation` as `entry.update` (F-9); until now the only source was `entry.list`, whose capability is
   `list`, so a grantee holding `notes` without `list` was refused by the CLI's `notes set` /
   `notes clear`. `notes.read` (both its "no note" and its normal answer) now also carries `generation`.
   Nothing new is exposed: `notes.write`'s own `conflict` already tells a `notes`-only caller
   `currentGeneration`. It is read **before** the note, so a write landing in between can only make the
   caller's generation stale (its write is refused as a conflict), never newer than the text it saw. The
   CLI takes the generation from `notes.read`; it falls back to `entry.list` only when the broker's
   answer has none (an older daemon) or when `notes.read` itself fails with `internal` (a damaged note —
   `notes.write` never reads the old note, so writing is how it is repaired).

**Consequences.** The audit feed still tells sessions apart. A running pre-ADR-077 daemon keeps leaking
until it is restarted; restarting kills every token. An existing vault still has `cmt_<32 hex>` strings
in its plaintext audit files (`SECURITY.md`, "Session token in the audit log") — dead credentials after
the restart, redacted when served, left in place so verification passes. `credmgr_list` (MCP) is
unchanged for agents: ids and names, no `entries`. A site that issues an 80-bit seed now works with
`totp.code`; a stored value under 80 bits is a typed refusal. The RFC 4226 deviation is deliberate and
scoped to stored seeds; revisiting it is a superseding ADR.

**Rejected.** *Hash or truncate the bearer for the actor*: a value derived from the secret keeps a
relationship to it that has to be argued safe; an independent random id needs no argument.
*Rewrite old audit lines*: it breaks the hash chain and the signed tip, the evidence the log exists to
keep. *Keep 128 bits and tell users to re-enrol*: the seed belongs to the service that issued it, not
to the user.

**Cost.** One more field on every token; a redaction pass on every audit write and read; `entries` is
absent for agents, so an agent that wants types must ask the person.

**Test.** `crates/core/src/totp.rs` (`an_80_bit_seed_is_accepted_and_fewer_bits_are_a_named_refusal`,
which includes the RFC 6238 known answer; `no_secret_length_digit_count_or_period_can_make_the_checked_constructors_panic`
— length × digits × period including `u64::MAX`, timestamps up to `u64::MAX`, junk strings and a
4096-byte seed; `a_stored_seed_may_be_padded_lower_case_or_grouped`);
`crates/brokerd/tests/audit_actor.rs` (4: `a_session_token_never_reaches_the_audit_files_or_any_audit_response`,
`a_record_written_by_a_leaking_build_still_verifies_and_is_never_served`,
`a_bearer_typed_into_a_reason_is_scrubbed_before_it_is_written`, `nothing_that_carries_a_bearer_prints_it`);
`crates/brokerd/tests/adr077_ops.rs` (7: `totp_code_on_an_unusable_seed_is_a_typed_refusal_never_a_dropped_connection`,
`a_locked_node_answers_node_locked_with_the_node_and_never_vault_locked`,
`a_locked_vault_still_answers_vault_locked`, `entry_list_carries_the_manifest_metadata_beside_ids_and_names`,
`entry_list_metadata_obeys_the_same_gate_and_filter_as_the_ids`,
`entry_list_metadata_is_returned_to_human_sessions_only`, `vault_status_says_whether_a_vault_exists`);
`crates/brokerd/src/token.rs`, `scope.rs` and `server.rs::an_op_that_panics_is_answered_as_internal_and_a_good_one_is_untouched`;
`crates/cli/tests/cli_parity.rs::a_notes_only_grantee_can_set_show_and_clear_without_the_list_capability`
and `notes_set_still_repairs_a_damaged_note`; the bridge's `error.rs`, `bridge_wire.rs` and `session.rs`
tests for `node_locked`, `initialized` and the redacted `Debug`; the endpoint matrix (the feed rows,
the all-secrets plaintext invariant including session tokens, the agent `entry.list` shape, the 80-bit
seed, the 72-bit refusal, `notes.read`'s generation); `scripts/e2e-journey.sh`, which greps the vault
directory for bearer-shaped strings.


## ADR-078 · Multi-field entries: a field document sealed as envelope version 2, legacy single values read in place

**Context.** ADR-013 decided that one entry holds many fields, and `03_DATA_MODEL.md §3` specified the
plaintext: an ordered `{id, label, value, type, masked}` array sealed as one envelope. Until this ADR
every entry was a version-1 envelope whose plaintext is the raw value; the field's label was used once to
bias inference and thrown away (`08_FIELD_MODEL.md §2`, §7), `fieldCount` was the literal 1, and ADR-073
built `entry.create_batch` in a single-value form that promised `fields: [...]`. The desktop design needs
a per-field `⋮` menu, one paste → one multi-field entry, field-level reveal and copy, and a free-text note
entry. Two constraints bind the design: **existing vaults open unchanged with no migration step**, and
**nothing about a field — its label, its type or its value — may reach the plaintext manifest or the audit
log.** Reading the code for this also found four defects that the new shape would have made worse; they
are fixed here (D13).

**Decision.** The numbering D1–D11 is cited from the code (`ADR-078 D5`, `D6`, `D11`); D12 and D13 are
the audit and integrity decisions.

1. **D1 · The payload.** A multi-field entry's plaintext is a canonical-JSON **field document**
   `{v: 1, entryType?, sensitivity?, fields: [{id, label, value, type?, masked?}]}`
   (`credmgr_core::fields`). A field id is `f_` plus 8 lowercase hex digits, minted by the broker and
   unique within the entry; `f_00000000` is reserved for the legacy field and never minted. A label is free
   text — empty is allowed, at most 200 characters (`LABEL_MAX_CHARS`), no C0 or DEL control character, any
   script. There is **no field-name vocabulary anywhere** (ADR-011): nothing looks a label up in a table;
   the one place a label is read at all is the entry-type *suggestion* (D10). The encoded document is at
   most 16 MiB (`ENTRY_DOC_MAX_BYTES`, the "envelope limit" `08 §3.5` always named, now enforced); there is
   no field-count cap. `decode` is strict: an unknown key, a `v` other than 1, no fields, a bad or duplicate
   id, or a label rule violation is an error, and an error names an index or a field id, never a label or a
   value.
2. **D2 · The discriminator is the envelope version.** The document is sealed as **envelope version 2**:
   the same suite, key derivation, header layout, nonce and tag as version 1. Only the version byte
   differs, and because that byte is already inside the AAD (`04 §3`), the payload kind is
   **authenticated** — flipping it fails the tag. Version 1 keeps meaning "the plaintext is one raw value".
   Nothing sniffs the plaintext, and nothing in the manifest says which kind an entry is: a v1 value that
   happens to look like a field document is one raw field holding that text. The version byte travels with
   the ciphertext into `pending/`, `history/`, the removal archive, the seal archive and backups, so no
   copy site needs to remember a flag. `envelope::open` stays version-1 only (a version-2 envelope is
   `UnsupportedVersion(2)`); `open_any` reports the kind.
3. **D3 · Legacy values are read in place.** A version-1 entry is read as a one-field document — id
   `f_00000000`, label `""`, the value verbatim — with an override pinned **only where inference without
   the lost label would disagree with what the manifest already shows**: its entry type, its sensitivity,
   and masking when the stored sensitivity is `high` or `critical`. The projection of the upgraded entry
   therefore equals its manifest entry exactly (an old password whose label was lost stays masked and
   `high`). Reading rewrites nothing; the first write re-seals the entry as version 2; nothing in a vault is
   ever migrated.
4. **D4 · Every new entry write is version 2** — `entry.create`, `entry.create_batch`, `entry.update`,
   `entry.rotate` and the four `field.*` operations — so a label is finally kept. A node's note
   (`notes.env`, ADR-072) stays version 1, and `notes.read` keeps refusing anything else.
5. **D5 · The broker never parses the bulk grammar.** Clients parse with `credmgr_core::parser` — the CLI
   directly, the desktop app through a *local* bridge command (`fields_preview`) that never reaches the
   broker, no socket, no audit record — show the preview, and send the previewed `fields` verbatim. "The
   preview is the contract" (`08 §5`): what was previewed is byte for byte what is written. One Rust
   parser serves every client; a broker preview op would write an audit line per keystroke and echo
   secrets over the socket. `parse_bulk_segments` keeps the `///` boundaries for the split toggle;
   `parse_bulk` is its flattening (P-18).
6. **D6 · Overrides, not cached answers.** A field's `type` and `masked`, and the entry's `entryType` and
   `sensitivity`, are stored **only as the user's override**; absent means "infer it now" (ADR-012), so an
   edit re-infers everything the user did not pin and no stale answer lives in the ciphertext. On the wire
   the string `"auto"` clears an override; JSON `null` is refused (the bridge drops nulls, so `null`
   could not mean "clear" end to end). A client sends `entryType` / `sensitivity` only when the user
   picked one — never an inferred value back.
7. **D7 · The manifest is the document's plaintext projection:** entry type, sensitivity, `fieldCount`
   and a new `hasTotp`. `ManifestEntry.hasTotp` is `#[serde(default, skip_serializing_if = "is_false")]`:
   it is written only when true, so every manifest, rotation snapshot and removal archive written before
   this ADR re-serialises **byte-identically** and still verifies (every signed store document verifies
   by re-serialising the parsed struct — a new field that serialised its default would have made every
   existing vault unopenable). `counts.totp` counts entries typed `totp` **or** carrying a TOTP-seed
   field, recomputed by one `ManifestBody::recount()` used by insert, update and remove. Labels, field
   types and values never enter the manifest. `hasTotp` reveals per entry what `counts.totp` and the
   `totp` entry type already reveal per node and per entry; accepted. `entry.list` is unchanged (it
   carries no `hasTotp`; `entry.get` does).
8. **D8 · Operations: 48 → 53.** `entry.get` (capability `read`: field ids, labels, types, masking, the
   entry's type and sensitivity and whether each was overridden — **never a value**; it needs the node
   key because labels are encrypted, so a locked vault is `vault_locked` and a locked node `node_locked`,
   with no approval path — labels are not worth a prompt; a held (tray) entry is `not_found`).
   `field.add`, `field.update`, `field.remove`, `field.reorder` (capability `update`; unlocked;
   generation-checked; the last field cannot be removed; `field.add` appends unless given a `position`;
   `field.update` takes a `patch` object so the keyword `type` need not be an argument name).
   `entry.create`, each `entry.create_batch` item, `entry.update` and `entry.rotate` take `fields` **or**
   the old `value`/`label` (exactly one), plus `entryType` and `sensitivity`; update and rotate take
   `field` to address one field and refuse an unaddressed `value` on a multi-field entry. `entry.reveal`
   takes `fieldIds` (each must exist — no partial answer) and answers `fields`, plus `value` **only when
   exactly one field is returned**, so single-value callers keep working; an approval covers the entry
   and `fieldIds` narrows what the approved reveal returns. `totp.code` and `totp.seed` take `field`
   (explicit, else the only field, else the one effective TOTP-seed field, else `malformed_request`).
   `entry.create_batch` validates and encodes **every item before the first write**, each document within
   16 MiB and the batch within 64 MiB (`BATCH_MAX_BYTES`). Exact shapes: `10 §4.3`, `18 §1`.
9. **D9 · Field edits keep history and are undoable.** Each `field.*` operation retains the previous
   envelope and its signed snapshot exactly as `entry.rotate` does (`entry.update` still keeps none), and
   `entry.undo` puts it back: the not-undoable message now reads "only entry.rotate, entry.remove and the
   field edits (field.add, field.update, field.remove, field.reorder) can be undone". The undo restores
   `fieldCount` and `hasTotp` as well as type, sensitivity and digest, records its system audit line under
   the **original** action (so undo-of-undo takes the same branch), and `rotatedAt` is stamped only by
   `entry.rotate`.
10. **D10 · The note entry** is entry type `note` — the variant formerly spelled `note-only`, which no code
    path ever constructed, so no vault holds it; `note-only` is still accepted on input. It is an
    ordinary entry whose single field is free text; inference *suggests* it for exactly one field labelled
    `note` or `notes` (R0). It is not a node note (ADR-072: one markdown document per node under the
    `notes` capability). Two additive inference changes accompany it: **R1** tightened to "a TOTP-seed field
    **and at most two fields**" so a server that merely carries a 2FA seed stays a `server`; the design's
    richer JavaScript type tree (`login`, `api`, `ssh`) was **not** adopted — the preview shows core's answer.
11. **D11 · Agents.** The MCP server gains `credmgr_get_metadata` (`entry.get`), `credmgr_field_add`,
    `credmgr_field_update` and `credmgr_field_remove`: **11 → 15 tools**. They are no wider than the
    `credmgr_update` and `credmgr_remove` an agent already holds. `field.reorder` is presentation-only and
    has no tool. `FORBIDDEN_OPS` is unchanged, and I-13 pins the reviewed 15-tool registry exactly. A
    read-only agent gets `entry.get` and `capability_not_held` for every `field.*`. Tool descriptions say
    that the broker does not parse `label: value` text — agents send structure.
12. **D12 · Audit.** One record per call, as before. An allowed call that names a field records its id
    (`field: f_…`, from `params.field`) and/or the ids it narrowed to (`fields: f_…,f_…` from
    `params.fieldIds`, at most 32, then `+N more`); only id-shaped strings are ever recorded. `params.fields`
    (objects carrying labels and values), `patch` and `value` are never read by the audit path, and a denied
    call records only its error tag.
13. **D13 · Integrity of the paths that trusted the old shape** (found while reading the code, fixed here).
    (a) `vault.pending_accept` trusted the unsigned sidecar's `fieldCount` and type: it now opens the
    pending envelope with the node key, takes type, sensitivity, `fieldCount`, `hasTotp` and the digest
    from the document, and uses the sidecar only for the name and the arrival time; an envelope that does
    not open is `internal` and leaves the tray untouched. (b) `node.seal` copied the original envelope's
    digest onto the resealed envelope in the orphan manifest (F5a): it now opens and reseals each entry as
    the same payload kind and records the digest of the **resealed** bytes. (c) `counts.totp` never followed
    an update (F5b): one recount. (d) `entry.undo` of a rotate did not restore `fieldCount` (F5c). (e)
    `vault.node_unlock` cleared the lock flag but left the node's hot key zeroed — harmless while update and
    rotate needed only the public key, fatal once they became read-modify-write; found by the endpoint
    matrix, fixed by re-deriving the key first.

**Consequences.** **A vault touched by this build cannot be opened by an alpha build:** alpha.6 refuses a
version-2 envelope (`UnsupportedVersion(2)`) and, for any manifest carrying `hasTotp: true`, drops the key
when it re-serialises, so its HMAC check reports the vault as tampered. `RELEASE.md` says so;
2.0.0-alpha.6 vaults open here with no migration step, and the first field edit re-seals just that one
entry as version 2. `entry.update`, `entry.rotate` and the field operations now **decrypt** the current
document (they already required the node unlocked; `06 §3`'s rule is that a legitimate update implies you
could have read what you replace). Field edits add rotation history, which nothing prunes yet (`entry.rotate`
already did). `scripts/emergency-decrypt.mjs` reads versions 1 and 2: version 1 prints the raw value,
version 2 prints the canonical JSON document verbatim (lossless), `--pretty` indents it. The desktop
bridge reaches all 53 ops (`entry_get`, `field_add`, `field_update`, `field_remove`, `field_reorder`
added; `entry_reveal`, `entry_create`, `entry_update`, `entry_rotate`, `totp_code`, `totp_seed` and
`entry_copy` gained optional arguments) and a local `fields_preview`; the CLI gains `field ls|add|set|rm|mv`
and `--field` / `--field-id` / `--all` / `--json` / `--bulk` selectors, with values still only ever from
stdin. The error vocabulary is unchanged at 25 codes.

**Rejected.** *A manifest flag saying "this entry is a document"*: it can desync from the ciphertext on an
interrupted write and has to be copied through every construction site (seal, accept, restore, undo,
archive, history). *Sniffing the plaintext for `{"v":1,…}`*: a raw value is arbitrary bytes, so no prefix
is unambiguous. *Migrating every entry to version 2 at unlock*: a signed-state write on the
authentication path, and a one-way door for every vault at once. *Parsing the bulk grammar in the
broker*: audit noise and secrets echoed over the socket. *A label vocabulary or per-type schema*: ADR-011.
*Caching the inferred type in the document*: a stale answer in ciphertext that no edit could correct.
*`null` to clear an override*: the bridge cannot send it.

**Cost.** One more envelope version to carry forever; read-modify-write on update; the document cap means
a single enormous field is refused rather than split; rotation history grows with every field edit.

**Open, recorded.** The broker still reads one request line with no size cap (`server.rs`) — with a
64 MiB batch that is a same-user memory-exhaustion path, to be bounded in a hardening change. An
entry-level `reveal` grant may never be usable (`entry.reveal` resolves node-level `reveal`; `entry.list`
honours entry-level grants). The broker's `search` matches names only, not labels or values. Decoded
documents are plain `String`s and are not scrubbed from memory on drop. If sensitivity ever gates
two-factor or reveal, lowering it must become human-only.

**Test.** `crates/core/tests/field_doc.rs` (P-13 … P-18) and `no_field_schema.rs` (the field-name grep
gate `08 §8` row 7 asked for); `crates/core/src/{fields,envelope,inference,parser}.rs` unit tests, including
the golden version-1 envelope; `crates/store/tests/alpha6_golden.rs` (the HMAC re-serialisation trap);
`crates/brokerd/tests/field_model.rs` (27), `entry_doc` unit tests, `seal_digest.rs` (F5a),
`field_seal_joint.rs` (field × seal × rotate × approval), `isolation.rs` I-27, I-28, I-29;
`crates/cli/tests/fields_cli.rs`, `no_secret_in_argv.rs`, `emergency_decrypt.rs` (the version-2 cases);
`crates/mcp/tests/i13_tool_registry.rs` and `schemas_match_the_broker.rs`; the bridge's `bridge_ops.rs`,
`fields_preview.rs`, `real_broker.rs`, `drift_guards.rs`, `ts_client.rs`; the endpoint matrix (53 ops);
`scripts/e2e-fields.sh`, including the segment that opens a vault written by the alpha.6 binaries.

## ADR-079 · K-7 closed: the orphan cold key, the orphan node at init, seal records in the signed registry, and an approval that never outlives a lock (the factor-bearing release deferred)

**Context.** K-7 (`PHASE8_AUDIT_REPORT.md §4`) left four things after ADR-069 closed the tray: no orphan
cold key (`04 §5.2`, `planned`); no `orphan` node in a vault `credmgr init` made, so `node.seal` answered
`internal` there; seal records held only in memory, so a restart forgot every in-window seal; and
approval-on-demand (ADR-042) could neither be decided nor completed on a wholly locked live vault — the
only Admin scope is the owner session that `lock()` revokes, and the value needs a root key a locked
durable vault does not hold. Reading the code for this also found the defects below (labelled as the code
cites them). `04 §5.2`'s KEK sketch also took "a fresh, single-use gate proof" as the HKDF salt, which
cannot reopen a stored blob.

| ID | Defect | Fixed |
|---|---|---|
| F-a | **Seal was not crash-safe**: files moved before the registry committed; a crash in between left a registry naming a node whose manifest was gone, and the vault would not unlock | commit protocol (D3) |
| F-b | **Orphan rows carried the wrong digest**: the original envelope's `sha256` was copied onto the new, resealed envelope (ADR-067) | D3, ADR-078 D13 |
| F-c | **A project with live sub-nodes could be sealed**, leaving dangling `parentId`s | `node.seal` refuses |
| F-d | **A sealed id could be re-created**; its files then collided with the archive and a later restore failed mid-rename | `node.create` refuses an id whose archive exists or whose seal record is live |
| F-e | **Node ids were unvalidated**: `../x` left the vault, and `removed-entries` / `entry-history` aliased `archive/<id>` onto the entry archives, so a later restore could `remove_dir_all` them | D5 |
| F-f | Restore re-inserted without re-validating workdirs or parent | D3 |
| F-g | `take_node_key_material` removed the hot key without zeroising it | zeroised |
| F-h | **The corpus overclaimed two-factor** ("RK alone opens nothing", "one TOTP code short of every credential"): true through `credmgrd`, false offline | `04 §2.1`, `07 §3`/`§4`, the release text |

**Decision.**

1. **The orphan cold key.** One X25519 keypair. The public half is `orphan.publicKey` in the registry; the
   private half is `keys/cold/orphan.key`, format **`CMCK` v1**, 98 bytes: `magic "CMCK" ‖ version 0x01 ‖
   kind 0x01 (root-derived) ‖ public key ‖ seal_under_root(RK, "credmgr/v2/orphan-cold/v1", private)`
   (`crates/core/src/cold.rs`; `kind 0x02` is reserved for a Secure-Enclave wrap). Opening derives the
   public key from the private half and requires it to equal **both** the header and the registry, so a
   swapped or rolled-back cold file is refused. The label differs from the node-wrap label, so a cold blob
   never opens as a node wrap and the reverse. It never enters the hot set or `node_wrapped_keys`; the
   loader treats `orphan` as public-only whatever is on disk (a stray `keys/nodes/orphan.key` is ignored
   and reported by `maintenance.verify`); unlock never opens it. `node.seal` opens it once, transiently, to
   prove it is recoverable before committing any data to it — a missing or mismatched cold key refuses the
   seal and writes nothing. **No unseal operation is dispatched** — reading orphaned data stays `planned`
   behind presence (R0, K-1). The gate proof is an authorisation precondition of that future path, never
   KDF input; this supersedes `04 §5.2`'s formula. **On the Software tier "cold" is enforced by the broker
   (R0, no operation, never resident), not by cryptography against a compromised broker:** RK, which is
   resident while the vault is unlocked (ADR-063), derives it. A hardware tier would rewrap it under a
   Secure Enclave key with a per-use presence ACL (`kind 0x02`) and drop the root-derived wrap.
2. **The orphan node.** `credmgr init` writes it — cold key, empty manifest, node record — before the
   registry, in ADR-061's crash-safe order. A vault an older build initialised has none and gets one on
   its first `node.seal` or on `maintenance.doctor`, **never as a side effect of unlock** (which stays free
   of signed-state writes). `maintenance.backup` includes the cold key. `maintenance.verify` (owner session
   only) reports as errors a cold key missing while the orphan is in the registry, one whose header does not
   match the registry or that does not open under the resident root key, and any seal record whose archive no
   longer matches it; and as warnings a stray cold file with no orphan node and a stray
   `keys/nodes/orphan.key` (ignored). `maintenance.doctor` regenerates a missing or damaged cold key only
   while nothing is sealed to the old one.
3. **Seal records are part of the signed registry.** `registry.sealed: {id → {v, node record, sealedAt,
   manifest binding, nodeKeySha256, orphanEntryIds}}`, under the registry HMAC **and** the external
   generation counter; the archive files (`archive/<id>/{node/, node.key, meta.json}`) sit beside it and
   are bound by it (a manifest binding and the node-key digest). A sidecar with its own HMAC would prove
   authorship, not freshness — an older record of the same id would verify and reinstate an older policy,
   the rollback `04 §6a` exists to stop. **Seal and restore are commit protocols** (`state/seal.rs`): the
   registry write is the commit point, made inside the op; the files written before it are unread until the
   registry names them, and the file moves after it are idempotent and rolled forward at the next load by
   post-verify housekeeping that never fails an unlock and never writes signed state. A move that did not
   finish is reported as `archiveMovePending` on `node.seal`; a restore that dropped a workdir another node
   now owns reports `workdirsDropped`. Sealing refuses a node with live sub-nodes, an unsafe id and an
   already-sealed id; restore refuses a sealed parent. Orphan rows carry the digest of the orphan envelope.
   The registry gains `format` (this build writes 2) and refuses a higher one (`RegistryFormatTooNew`); a
   build older than this one ignores `sealed` on read and drops it on its next write, so **downgrade below
   2.0.0-beta.1 is unsupported** (it would lose the seal records; the archives stay on disk).
4. **Approval on demand: it never outlives a lock (4a), and a locked vault no longer promises what it
   cannot keep.** The value is decrypted and **staged when the decision is made**, while a root key is
   resident; the retry only hands it over and never derives a key (removing the `internal` the retry used to
   answer). `lock()` — explicit, idle or sleep — expiry and consumption each zeroise every staged value,
   so a staged approval never survives a lock; a decision that races a lock stores nothing. A reveal or a
   decision on a **wholly locked live vault** answers `vault_locked` and releases nothing instead of an
   `approval_pending` nothing could complete; an approval whose vault locked before the requester came back
   is `approval_denied` with reason `"locked"`. Request ids are 128-bit. Fail-closed stays the default
   throughout: undecided at 120 seconds is denied. In-memory fixtures (ADR-042's tests) behave as before.
5. **Node ids** are `[a-z0-9][a-z0-9_-]{0,63}`; `global`, `orphan`, `removed-entries` and `entry-history`
   are reserved. Enforced where an id is chosen (`node.create`); an id that already exists is never refused
   at load — a weaker path-safety check guards the file moves for those.
6. **Root-key rotation (ADR-076) re-wraps everything this ADR added.** A rotation re-seals the cold key
   under the new root (the orphan keypair itself is unchanged, so no orphan envelope is re-encrypted),
   refreshes each seal record's bindings to the re-signed archived manifest and key, re-signs each
   archive `meta.json`, and refuses to proceed while a sealed node's files are not yet all in its archive.
   Joint tests: seal → `rotate_root` → restore byte-identical; init → `rotate_root` → the cold key opens
   under the new root only.

**Shipped and deferred.** This change ships items 1–3 and 5–6 and the **4a half** of item 4. The **4b half
is deferred and documented, not built:** `vault.approval_decide` authorised by the unlock factors (passphrase,
plus a TOTP code — never a recovery code) so a single value can be released while the vault stays locked,
`vault.approval_get {request}` so the human sees the broker's own description of the request first, and
`credmgr approve|deny`. It would add one operation (53 → 54) and a tokenless door that must be authorised by
factors rather than origin (a tokenless caller is always `Origin::Agent`), so it needs its own review. Until
it exists, an agent's request on a wholly locked vault is refused with `vault_locked` and the person unlocks
and lets it retry; approval-on-demand remains a *node*-lock feature (ADR-042) and a *vault-unlocked* one.
**Nothing in the product calls `vault.approval_decide` today** — the desktop app has no approval screen and
the CLI no `approve` — so even there a request is decided by the person unlocking the node, or expires and is
denied after 120 seconds; the operation is reachable from the bridge and the socket, and from no control.
Also not built: purging an expired archive (`maintenance.doctor` does not purge), a `keystore` field in
`vault.status`, a `sealed` list in `graph.snapshot`, and an offline recovery of orphaned entries
(`emergency-decrypt.mjs` reads live nodes only; whether it should also read orphaned ones is an open
product decision — it would turn "reachable only by a person at the machine, through presence" into "or
offline, with the recovery card").

**Rejected.** A *passphrase-derived* cold key: it protects only against a one-shot memory capture of an
unlocked broker, strands sealed data when only the recovery code survives, and needs the passphrase where a
write is not allowed. *Seal records in an HMAC'd sidecar beside the archive*: authorship without freshness.
*Creating the orphan node at unlock*: a signed-state write on the authentication path. *Keeping RK, the
passphrase or a node key resident while "locked"*: that is not a lock (R-3). *Re-deriving RK at the retry*:
a locked durable vault refuses it by design. *Letting a gate recovery code approve*: its burn cannot be
persisted while locked. *An approval list readable by any tokenless caller*: it would show other nodes'
entry names to agents.

**Consequence.** K-7's four items are closed or honestly bounded: sealing works in a vault `init` made and
survives a restart; a crash during seal or restore no longer locks the owner out; an approved value cannot
outlive a lock. R-9 changes from "unrecoverable by anyone" to "recoverable with the cold key, by no shipped
path" — the reveal stays behind presence (K-1).

**Bound.** The cold key is as strong as RK: anyone who can derive RK — the passphrase or the recovery code
plus a copy of the vault directory, or a memory capture of an unlocked broker — can open orphaned data, as
they can already open everything else. **Two-factor does not participate in that:** it is enforced by
`credmgrd`, not by the encryption (`04 §2.1`). One approved value can sit in an unlocked broker's memory for
at most the request's remaining time to live, and is dropped by any lock.

**Test.** `crates/core/src/cold.rs` (round trip, wrong RK, header and registry mismatch, tamper,
truncation, label separation); `crates/brokerd/tests/seal_durable.rs` (37: seal → restart → restore
byte-identical, day 8, tamper, rollback and swap refusals, every crash window, children, a re-created id, a
sealed parent, a workdir conflict, the format refusal, orphan digests); `approval_locked.rs` (19);
`seal_digest.rs`; `field_seal_joint.rs`; `rotate_root.rs` (the joint seal and cold-key tests);
`node_ops.rs` (node-id grammar); `crates/store` (registry format, backup includes the cold key);
`scripts/e2e-journey.sh` (seal → restart → restore with the real binaries); the endpoint matrix, whose
`node.seal` and `node.restore` rows carry no known-gap marker any more.

### Amendment (C1, 2026-10-17) — four defects found after the decision (three in the K-7 commit protocol, one in decoded-value hygiene)

Found by the post-iteration-3 audit and fixed with a test that failed first (each test was mutation-checked:
the fix removed, the test seen to fail). No wire shape changed.

| ID | Defect | Fixed |
|---|---|---|
| **C1-a** | `node.seal` and `node.restore` changed memory, then committed, without holding the persist lock between the two. A write-through (`entry.set`, say) landing in that window persisted a half-sealed state, or was overwritten by the seal's commit. | Both now take `lock_persist()` before the memory change and commit with `persist_with_root_edit_locked`, releasing only after the commit and any rollback. Tests: `seal_durable.rs` `a_write_through_cannot_slip_into_a_seals_window_and_the_vault_stays_whole` and `…_a_restores_window_either`, which pause the seal at its window through the `test-utils` seam `SealPause` and race a write against it. |
| **C1-b** | `take_node_key_material` removed a hot key from its map and then zeroised the moved copy; the bytes left in the bucket were never wiped. | `wipe_then_remove` zeroises the value where it sits (`get_mut`), then removes it. Test: the address `zeroize` ran on equals the address in the table. |
| **C1-c** | `reveal_via_approval` consumed the human's one-time approval before it had built the answer, so a malformed `field` in the retry burned an approval the human had given. | The answer is built first through `with_approved` (a non-consuming read); `take_approved` runs only after it succeeds. Test: `a_malformed_field_id_in_the_retry_does_not_burn_the_humans_approval`. |
| **C1-d** | A decoded `FieldDoc` left its value (and label) in freed heap when dropped. | `FieldDoc` now implements `Drop` through a public `wipe()` that zeroises both. Test: `field_doc.rs` `wiping_a_field_clears_its_value_and_label`. **Known risk, bounded:** the workspace forbids `unsafe`, so the one-line `Drop` → `wipe` wiring is verified by review, not observed; the wipe is not a guarantee against copies the allocator or a `Clone` already made before the drop. Owner: backend; resolution: none planned. |

**Known risks left by the C1 verifier (independent read, 2026-10-17; none is a regression, all pre-date C1):**
(1) `node.create` takes no lock on its parent and `node.set_workdirs` none on a claimed workdir, so during a seal's or restore's window a child or a duplicate workdir can be created and then committed with it (the persist lock stops *other persists*, not other in-memory writers); owner: backend; resolution: lock the parent / workdir claim in C2's backend sweep or file as a beta.1 issue (C5). (2) Hot keys are still copied without a wipe when the whole map is replaced on unlock, when an `insert` overwrites a value, and on `HashMap` rehash; bounded by the process boundary (the broker is a local, single-user daemon), resolution: none planned for beta.1. (3) `release-lib.sh` `inspect_app` trusts `CFBundleExecutable` from the app it inspects; a hostile value or symlink can hang the verifier (a denial of service of the verifier only, run on artifacts the operator built); resolution: validate the path stays inside `Contents/MacOS` in C3. (4) An approval is keyed by (node, entry), not by the requesting session.

## ADR-080 · Two additive human-only fields for the desktop: `meta.sealed` on `graph.snapshot` and `hasTotp` on `entry.list` rows

**Context.** The app shows a recovery countdown for every sealed node and a TOTP badge on entry rows. The
first needed the registry's seal records, which only `node.restore` could reach; the second needed a fact the
manifest already holds (`has_totp`, ADR-078) but the list did not return. Both could have been new broker
ops; both are better as fields on reads the app already makes.

**Decision.**

1. `graph.snapshot` `meta` gains `sealed: [{id, label, sealedAt, expiresAt}]`, sorted by id, where
   `expiresAt = sealedAt + RECOVERY_WINDOW_SECONDS`. It is present **only** when the caller is not
   `Origin::Agent` **and** holds the `Admin` capability; otherwise the key is **absent** (not empty). It reads
   the signed registry's seal records, so it survives a restart.
2. `entry.list` `entries[]` rows gain `hasTotp: boolean`, human sessions only, under the same gate and filter
   as the rest of the row (ADR-077). It carries no seed and no code.
3. No new op, no new error code, no new MCP tool: **53 broker ops · 25 error codes · 15 MCP tools** are
   unchanged. An agent never sees either field, and the agent-side list shape stays `node, ids, names,
   generation`.

**Consequences.** A client built against the alpha ignores both fields. The desktop bridge types them
(`SealedNode`, `EntryListRow.hasTotp`). Tests: `seal_durable.rs`
`the_snapshot_lists_sealed_nodes_to_the_owner_across_a_restart_and_not_to_an_agent` and `adr077_ops.rs`
`entry_list_marks_an_entry_that_carries_a_totp_seed`, both mutation-checked.

**The record runs through ADR-081; the next number is ADR-082.** (ADR-078 and ADR-079 were reserved on
2026-10-02, while the parallel work on the field model and on K-7 was in flight, so that no other decision
would take either number; both are decided here.)

## Still needed from the operator (not blocking the build)

| # | Item | Blocks |
|---|---|---|
| **O-1** | ~~The real **EVM and BTC donation addresses**~~ · **RESOLVED** (verified 2026-09-13) | ~~Publishing `DONATE.md`. Deliberately invalid placeholders ship until then — a guessed address sends real money to nobody. **Not a build blocker.**~~ Real EVM/BTC/Solana/Tron addresses landed in `e49b533`; `v1/DONATE.md` and `v2/DONATE.md` both carry them, and no `REPLACE_ME_BEFORE_PUBLISHING` placeholder survives anywhere in the tree. |
| **O-2** | ~~The **GitHub org/repo name** for the public V1 and V2 repos~~ · **CLOSED** (verified 2026-09-13) | ~~Filling the clone URL in `README.md` and `21 §3`. **Not a build blocker.**~~ The repo is `Cryptosours/credmgr` — private, pushed. |
| **O-3** | An **Apple Developer ID** and a **Windows code-signing certificate** | Signed releases (`21 §2`). Needed at Phase 8, not before. **Still open.** |

O-1 and O-2 are kept as rows, struck rather than deleted: this is an append-only record, and a
reader who was told an item was outstanding is owed the correction where the claim was made.
**O-3 is the only item still outstanding.**

---

## Superseded open-questions section (kept for the record)

The original wording of Q-1…Q-7, with the defaults that were in force before 2026-08-05:

## Open questions for the operator

Answer at any time; each has a working default so nothing is blocked.

| # | Question | Default if unanswered |
|---|---|---|
| **Q-1** | Should `acme` / `contoso` / `northwind` be split into sub-nodes at migration (e.g. `acme → testnet, mainnet`)? | **No.** Migrate flat; split later, deliberately. |
| **Q-2** | Should entry *names* be encrypted, leaving only counts in the clear? Costs: search needs an unlock; the graph keeps working either way. | **No** for V2.0 — names stay in the manifest, recorded as AR-1. Pass 2 reconsiders. |
| **Q-3** | Default auto-lock: 15 min? | **15 min.** |
| **Q-4** | Should Lite be the default mode for you specifically, or Pro? | **Lite**, with a one-click switch. |
| **Q-5** | Keep the long `PROJECT_NAME` credential names, or rename to short names inside nodes? | **Keep**, with short aliases registered. |
| **Q-6** | Should the wallet node get `requireTwoFactor: always` (2FA even to list)? | **Yes** for entries containing a seed phrase or private key. |
| **Q-7** | Is a 45-day V1 retention window right before archiving? | **Yes.** |

## ADR-081 · The desktop first run may skip the recovery-code retype, and the GUI's passphrase floor is four characters

**Context.** ADR-061 made vault creation two-phase so the operator proves they have the recovery code before anything is
written. In the real-app pass the operator asked for setup that never blocks: skip the retype, skip ticking the boxes, a
shorter passphrase, a second factor that stays optional.

**Decision.**

1. `vault.init_confirm` is unchanged: it still requires the recovery code and refuses a wrong one. The **desktop** may
   send the code it is already showing when the person chooses "Skip for now" or leaves the retype empty. The broker's
   match check therefore proves possession of the code **only when the person retyped it**; for a skip it proves nothing,
   and the screen says so ("optional … a lost passphrase cannot be recovered"). The CLI (`credmgr init`) still requires
   the retype. `04_CRYPTO_AND_KEYS.md §2.3` step 3 describes the broker's rule, not the GUI's choice.
2. The GUI's passphrase floor is **4 characters** (was 8), with "8 or more is recommended" shown and never enforced. The
   broker never had a minimum (`credmgr init` takes any non-empty passphrase); the floor is a UI mistake-guard.
3. The ten gate recovery codes need no acknowledgement (no tick, "Skip for now"); they are still shown once and never
   stored. The second factor stays optional ("Enrol later").
4. **Not decided here:** a vault with no passphrase (the passphrase wraps the root key; an unprotected tier is a crypto
   design change needing its own ADR and review) and mandatory 2FA.

**Consequences.** A person who skips the retype and loses the code has no second-factor reset; one who loses the
passphrase has no recovery at all (unchanged). Tests: `wp-a-firstrun.spec.ts`, `tests/real/first-run-options.spec.ts`
(a real four-character vault with the retype skipped unlocks).

## ADR-082 · A milestone-only donation reminder and a sealed pack of cosmetic extras opened by an e-mailed supporter code (supersedes the "no toast, no code" part of ADR-075 §6; ADR-074 stands)

**Context.** The first desktop import removed the design's donation toast and its shared unlock code, and the repository rule
read "one static entry, never a banner". On 2026-10-18 the owner decided, in the front-end team's workstream, that the toast and
the supporter code stay: cosmetic extras only, nothing functional gated.

**Decision (amended 2026-10-18 after design batches B14/B15; the numbering ADR-083/084 was already taken, so this amends ADR-082 in place).**

1. **The reminder appears only at entry milestones**, at most three times in the life of an install: 50 entries and 14 distinct
   unlock days, 150 entries and 45 days, 300 entries and 90 days. It is shown after an unlock (about six seconds), never over a
   dialog, never while the vault is locked, never in a game, never twice in one day; it has no countdown and steps aside from the
   control in use. "Don't remind me" turns it off for good. A jump from below 50 to 300 asks once for the highest milestone and
   marks the lower ones passed. Counting days stores a calendar date only.
2. **The extras ship sealed.** The cosmetic pack is inside the app as AES-GCM ciphertext (key from PBKDF2-SHA-256, 200 000
   rounds, of the upper-case trimmed code), **data only**, never evaluated. A supporter code, e-mailed after a donation, opens it
   once on the device; the derived key is then kept (`credmgr_extras_key`) so the extras stay open after relaunch. The code is not
   in the source, a file or a log. Rotating it means the owner re-seals the pack in the design project and ships a new build.
3. **Rule: the pack never holds code or anything functional.** Alternate marks, glyph weight, halos, badge, node shapes, node and
   link colours, entry-dot palette, graph backdrop, unlock flourish and CredPong trail only. **Nothing functional is ever gated**
   (ADR-074 stands: MIT for everyone).
4. The donation proof (screenshot and transaction hash) is sent by the donor's own mail client; the app makes no request, so
   the CSP is unchanged. Window storage keys: `credmgr_cosmetics`, `credmgr_donate_unlocked`, `credmgr_extras_key`,
   `credmgr_usage` (dates and flags, no name, id or count), `credmgr_keys` — all in `PRIVACY.md`.
5. A shared code can be guessed offline (threat T12/T16, accepted: the pack is cosmetic).

**Consequences.** `DONATE.md`, `PRIVACY.md` and `design-upstream/PROVENANCE.md` carry the design project's text. The importer
(`scripts/dc/import.mjs`) must accept zero unlock-code values and refuse any file that reintroduces `donateUnlockCodeVal`.
`pstore.test.ts` `DOCUMENTED` gains the three new keys. The repo rule "one dismissible toast" in `v2/CLAUDE.md` is restated.

## ADR-083 · `privateNames`: what a non-owner or agent sees (ACCEPTED 2026-10-18)

**Context.** `node.policy` stores `privateNames` but nothing reads it (listed under `notEnforced`). The design needs a shape.

**Proposal.** For a node with `privateNames` set, every reader that is not the owner (agents, MCP, grants) gets the node as an
opaque row: `{ "id": "<node id>", "nameHidden": true, "name": null, "entryCount": 7 }` in `graph.snapshot`, and
`entry.list` for that node returns `{ "entries": [], "nameHidden": true, "count": 7 }`. Counts stay (the graph needs a size);
names, labels and notes do not. The owner (human session) sees everything and a `nameHidden` badge. Enforced in the broker,
once, next to the existing scope filter; an additive field, so the endpoint matrix grows by fields, not ops.

**Decided (owner, 2026-10-18).** Names are hidden and counts kept; **a count below 3 is hidden too** (`entryCount: null`, `countHidden: true`), so a one- or two-entry node reveals no size. **Status: BUILT 2026-10-24** (milestone 2.0.0-beta.2, `part4_private_names.rs`). Enforced once, in `ops.rs`
(`hides_names` / `node_hides_names`): the reader is "not the owner" when it is not a live login session
(`state.is_owner_session`) — agents, MCP, every tokenless cwd process and any grantee alike. The surfaces that put a
name on the wire are `graph.snapshot` (the opaque row: `id`, `nameHidden`, `name: null`, `label: null`, `kind`, `depth`,
`parentId`, `entryCount`, `counts {entries, totp: null}`, `gate`; `countHidden: true` below three; the owner's row gains
`nameHidden: true` only on a private node), `entry.list` (`ids: [], names: [], entries: [], nameHidden, count`), `search`
(the node contributes nothing), `entry.get` (`name` and every field `label` become `null`), `vault.pending_list` (`name`
becomes `null`), `notes.read` (`markdown: null`; the `generation` stays so a holder of `notes` can still write one) and
`audit.tail` (for a non-agent non-owner, `entry` and `detail` of a private node's records become `null`; the agent feed
never carried them). `entry.undo` / `entry.restore` answer `restoredName: null` (and `restored.name: null`, and an empty name in the
`entry_exists` refusal) to such a reader — found by the independent review the same day. `entry.reveal` is **not** changed: a value the reader was explicitly granted comes with its labels,
because a label is how a value is read. `node.policy` no longer lists `privateNames` in `notEnforced` (the list is empty,
the key stays). No new op: 53 ops before this change, unchanged by it.

## ADR-084 · One canonical form for names, shared by broker, app and CLI (ACCEPTED 2026-10-18, closes threat T4)

**Context.** Uniqueness is an exact string compare in `ops.rs` (lines near 758, 1037, 2274) and the pending tray, while the
window folds names itself. An agent can write a look-alike (Cyrillic `а` for Latin `a`) through the broker.

**Proposal.** One function `canonical_name(&str)` in `crates/core`: strip bidi and zero-width controls, NFKC, Unicode lower-case
fold, then the look-alike table in `FRONTEND_THREAT_MODEL.md` ("Look-alike table"). ASCII `0`/`o` and `1`/`l` are not folded.
Every uniqueness check (node, entry, pending tray) compares canonical forms and the existing duplicate error is returned; the
stored name keeps what the person typed. The window's `foldName` is replaced by a call into the same table (generated or
test-pinned so the two cannot drift). Tests: table pairs, mixed-script names, an agent write of a twin is refused.

**Decided (owner, 2026-10-18).** Look-alikes are refused (duplicate error); the broker **also returns a warning** on names that mix Latin with Greek or Cyrillic, without refusing them. **Status: BUILT 2026-10-24** (milestone 2.0.0-beta.2): `credmgr_core::names::canonical_name` (idempotent by construction: it
iterates to a fixed point) and `mixes_scripts`, the table `names::LOOKALIKES` pinned to the threat model's "Look-alike
table" by `crates/core/tests/names.rs`. Used at `create_entry` (so `entry.create`, `entry.create_batch`'s items and the
locked-write tray), inside a batch (a twin of an earlier item is `malformed_request`, as an exact duplicate was), at
`entry.restore` / `entry.undo` (a collision with a twin is the existing duplicate refusal, and `keep-both` picks a free
canonical name), at `vault.pending_accept` and at the orphan name collision on `node.seal`. Node ids are ASCII by
grammar and cannot be look-alikes; node labels are not unique and are human-set, so they get the warning only. The
warning is an additive `warnings: ["mixed_script_name"]` on `entry.create`, `entry.create_batch`, `node.create` and
`node.update`; the CLI prints it on stderr. The invisible-character list also covers the combining grapheme joiner, variation selectors, tag characters, Hangul fillers and
Mongolian selectors (review finding: `payroll` + U+FE0F was a visible twin). Two consequences of the owner's table that the
review named, accepted as decided: the Unicode lower-case fold makes `API_KEY` and `api_key` one name (an older vault that holds
both keeps them; only a new create is refused), and dotless `ı` folds to `i`. The window's `foldName` is **not** replaced here (no desktop UI work in this
change); the table is the shared source and the pin test is on the Rust side.

## ADR-085 · `requireTwoFactor` is enforced per node: who is asked, for what, and how a person answers mid-session

**Context.** `node.policy` stored `requireTwoFactor` (`never` · `reveal` · `always`) and reported it as `notEnforced`;
`07_TWO_FACTOR.md §2` and `06 §10.4` described the intent — a node can insist on a fresh second factor — and recorded that
the broker never acted on it. The only second factor in the system is the vault gate (`GATE_SCOPE_VAULT`), checked at
`vault.unlock`; there was no way to prove it again while the vault was open.

**Decision.**

1. **Asked only when there is something to ask.** The policy is consulted only when the vault gate is *confirmed*. With no
   gate enrolled nothing is asked and nobody is locked out (the "refusal to build a lockout" of `07 §4` is unchanged).
2. **Levels.** `never`: nothing. `reveal` (the default): before a **value** leaves the vault — `entry.reveal`, `totp.code`.
   `always`: additionally before any **read** of the node — `entry.list`, `entry.get`, `notes.read`, `vault.pending_list`;
   `search` skips an `always` node rather than failing the whole query. `graph.snapshot` and `node.list` stay open: the graph
   must render a locked vault (`VAULT_GRAPH_SPEC.md`), and they carry no name once `privateNames` is on.
3. **Who satisfies it.** The vault owner's login session (it passed the gate to exist), or a live **elevation** — a fresh
   gate verification within `DEFAULT_ELEVATION_SECONDS` (5 minutes, `07 §5`). Anyone else — an agent, MCP, a grantee —
   gets `two_factor_required` (`challenge: "totp"`, `scope`, `expiresIn`) until a person proves the second factor.
4. **The step-up.** `vault.gate_verify` called by an already-logged-in owner session is not finishing a login: it checks the
   code the same way (TOTP window with the replay ledger, or a recovery code once), under the same backoff, grants the
   elevation, mints **no token** and answers `{locked: false, elevated: true, expiresIn}`. No new op. The CLI is
   `CREDMGR_TOKEN=… credmgr gate verify <code>`.
5. **The default has teeth.** Because the default level is `reveal`, a vault with a gate now answers a tokenless agent's
   `entry.reveal` with `two_factor_required` once five minutes have passed since the owner last proved the factor. That is
   `07 §2`'s "values gated" taken literally, and it is the intended behaviour; the remedy is the step-up above, or
   `--require-two-factor never` on a node whose values an agent should read freely.

**Not decided here / left.** A per-node gate secret (`07 §3`) and a per-node elevation; the window has no screen for the
step-up yet (the CLI and the socket have it). Presence for the strongest levels stays `planned`. A step-up when no gate is enrolled is `malformed_request` ("nothing to
verify"), not a failed login: it must not feed the unlock backoff (review finding).

**Consequences.** `node.policy` answers `notEnforced: []`. `07_TWO_FACTOR.md §2`, `06 §10.4` and `05` row "Per-node always
require 2FA" are corrected. **Tests:** `part4_two_factor.rs` (reveal vs always vs never, no gate = nothing asked, the step-up,
a wrong code, the window closing, and the policy and gate surviving a restart); mutation-checked.

## ADR-086 · Undo of a field change: no new op — `entry.undo` already covers it, answers `ok` and `restored`, and a field edit is undoable for seven days

**Context.** The 2026-10-18 design drop asked for `field.undo` (4.5). Reading `ops.rs`: ADR-078 already made
`field.add`, `field.update`, `field.remove` and `field.reorder` retain the pre-change envelope and snapshot, and
`entry.undo` (addressed by the audit id that every changing call returns in `audit`) already restores all four. What was
missing was the shape the window wanted and the seven-day window a removed entry has.

**Decision (the smaller of the two options).** **No `field.undo` op.** `entry.undo` is extended, additively:

1. Its answer gains `ok: true` and `restored`: `{"action": "field.remove", "entry": "e_…", "fieldCount": 3}` for a field edit or
   a rotation, `{"action": "entry.remove", "entry": "e_…", "name": "…"}` for a removed entry. The old keys
   (`generation`, `undoneToGeneration`, `restoredName`) are unchanged, so MCP `credmgr_undo` and the CLI work as before.
2. A **field edit** can be undone for **seven days** from when it was made (the retained snapshot's signed
   `recordedAt`); after that `entry.undo` answers `not_undoable` ("a field edit can be undone for seven days only") and
   changes nothing. A rotation's undo keeps its old behaviour (no limit); undoing an undo restarts the clock.
3. The audit id the window needs is the `audit` member of the changing call's own answer; the bridge already passes it.

**Consequences.** 53 ops, 15 MCP tools and 25 error codes are unchanged. **Tests:** `part4_field_undo.rs` (each of the four
ops taken back and the state read back through the real reveal; the removed entry's `restored`; day 6 allowed, day 13 refused
with the edit left in place; a rotation older than a week still undoes).

## ADR-087 · `util.generate`: the password generator lives in the broker

**Context.** The design drew a generator (4.6). A generator in page JavaScript would use `Math.random` or `crypto.getRandomValues`
in a realm that also runs third-party game code (T7) and would put the value in the DOM from the first millisecond.

**Decision.** A new broker op, **`util.generate`** (54 ops), implemented in `credmgr_core::generate` and called with the
operating system's generator (`OsRng`); the algorithm is pure and takes the random source as a parameter, so tests use a
deterministic one.

1. **Params** (all optional; an unknown key is refused, not ignored): `length` 8–128 (default 20; outside it `malformed_request`),
   `symbols` (default true), `pronounceable` (default false).
2. **Random mode:** lower, upper, digits, plus the shell-safe set `!@#$%^&*-_=+?` when `symbols`; at least one of each enabled
   class, the rest uniform over the union, positions shuffled, all by rejection sampling (no modulo bias).
   **Pronounceable:** consonant, vowel alternating (18 consonants — no q, x or y — and 5 vowels), `-` after every fourth
   letter when `symbols`.
3. **Answer:** `{value, length, symbols, pronounceable, entropyBits}`; `entropyBits` is `⌊length × log₂(pool)⌋` (the exact figure
   for pronounceable mode, which is weaker — 64 bits at 20 characters — and says so).
4. **Who:** a caller holding `create` or `update` (a generator is a step towards writing). Not an MCP tool (15 stays); not on
   the forbidden list either — it reads nothing. The value is in the answer only: the audit line is `util.generate allow` and
   nothing else, and nothing is stored.
5. **The value reaches a field only through the broker** (`field.add`, `field.update`, `entry.create`), is shown masked, and the
   window never copies an unmasked generated value to the clipboard (`entry_copy` is the only clipboard path for values).

**Consequences.** CLI `credmgr generate`; bridge command `util_generate`; endpoint-matrix rows; `10_API_AND_MCP.md`,
`18_ENDPOINT_INDEX.md`. **Tests:** `generate.rs` unit tests (bounds at both ends, classes present, charset, entropy, uniformity,
bias zone, pronounceable shape, no shell-hostile character), `part4_generate.rs` through the real wiring, the bridge's
`util_generate_sends_only_the_options_it_was_given…`, the drift guards.

## ADR-088 · Approval 4b: one request is decided with the unlock factors while the vault stays locked

**Context.** ADR-079 built 4a (a staged value never outlives a lock; a wholly locked vault answered `vault_locked` and recorded no
request) and deferred 4b: no one could approve while the vault was locked, so approval-on-demand was a node-lock feature only.

**Decision.**

1. **A reveal on a wholly locked live vault now records the request** (`approval_pending`, with a message naming the
   command) instead of answering `vault_locked`; there is now something a person can do about it.
2. **`vault.approval_decide`** gains two optional params: `passphrase` and, when a gate is confirmed, `code`. With a `passphrase`
   the decision is authorised by the factors, not by a session: it works **only while the vault is locked**
   (`malformed_request` otherwise — unlocked, use the session), needs no capability, creates no session, token or elevation,
   and derives no hot key. The passphrase yields the root key transiently; it opens the one value being released (staged
   exactly as an owner decision stages it), signs one audit record, and is dropped.
3. **Factors.** Wrong passphrase → `wrong_passphrase`. A confirmed gate with no `code` → `two_factor_required`; a wrong code →
   `gate_verification_failed`. **A recovery code is refused** (burning it cannot be persisted from here). The spent TOTP step is
   written through to disk before the value is staged, so a restart cannot accept it again. Both failures count toward the
   per-uid backoff `vault.unlock` uses (the server treats a factor-bearing decide as an auth path).
4. **Audit.** The generic per-request record needs a resident root key a locked vault does not have, so the op writes its own:
   actor `Factors`, `vault.approval_decide`, the node and entry, detail "approved|denied with the unlock factors; the vault stayed
   locked". Never a value, never the request id.
5. The value then leaves exactly as before: the agent's retry hands over the staged value once and consumes it; the 120-second
   TTL, the lock epoch and "an approved reveal with an unknown field id does not burn the approval" (C1) all still hold, and a
   test now pins the last for the locked flow too (a list that names an unknown field beside a good one).
6. CLI: `credmgr approve <request> [--deny] [--code <n>]` (passphrase on stdin; the login token is deliberately not sent).
7. **Hardening from the independent review (same day).** A request is recorded only for an entry that exists in the node's
   manifest (`not_found` otherwise), so the table holds at most one slot per real entry and an agent cannot grow it with invented
   ids on a locked vault. The factor decision's audit record is written **before** the value is released and its failure refuses
   the decision (a release with no record is worse than no release); a decision that then does not take effect adds a `deny`
   record. Named, not fixed: `approval_factors` does not run the interrupted-rotation recovery `vault.unlock` runs (a half-rotated
   vault that locked itself after a failed roll-forward); `canonical_name` runs per existing name per create with no name-length cap.

**Not built here:** `vault.approval_get` (the person seeing the broker's description of the request before deciding) — built later as the 55th op by ADR-090; until then the request id was the agent's output and the decider approved by id. **Tests:**
`part4_approval_factors.rs` (9: release while locked, wrong passphrase and the backoff, gate with no/wrong/recovery code,
spent step across a restart, deny, closed paths, unknown field ids, audit, TTL); `approval_locked.rs` updated (3 tests changed
from `vault_locked` to the new answers); the endpoint matrix.

## ADR-089 · K-7 follow-ups: seal and restore re-check under the persist lock, `node.create` / `node.set_workdirs` wait for it, and expired seals can be purged

**Context.** C1 (ADR-079 amendment) made seal and restore hold the persist lock from their first memory change to the end of the
commit. Two things were left (the C1 verifier's known risk 1): their pure checks ran *before* the lock, so a `node.create` under
a node being sealed, or a `node.set_workdirs` claiming a directory of a node being restored, landed between check and commit and
was written into a registry that contradicts it (a vault that fails its next load). And WP6 — the purge of expired seals — was
not built.

**Decision.**

1. **Re-check under the lock.** `seal_node_durable` re-asks "has this node live sub-nodes?" once it holds the persist lock and,
   if so, removes its pre-commit files and refuses with the same `has sub-nodes` message. `restore_node_durable` recomputes its
   candidate (workdirs another node now owns are dropped and reported, a gone parent refuses) under the lock and, on refusal,
   moves the files back to the archive.
2. **The other side.** `node.create` and `node.set_workdirs` take the persist lock (`hold_persist_lock`) for their check-and-insert,
   never across the write-through the dispatcher makes afterwards. Lock order is unchanged (node write locks, then the persist lock).
3. **Purge (WP6).** `maintenance.doctor` with `purgeExpiredSeals: true` (opt-in, Admin on `global`, vault unlocked and on disk)
   destroys the retained originals of every sealed node whose seven days are over: the registry write that drops its seal record
   is the commit (under the node's write lock and the persist lock), then `archive/<id>/` is removed. The entries stay in `orphan`
   (sealed to the cold key); only the way back to the live node ends, and the id becomes free for a new node. `apply: false` lists
   `would-purge-expired-seal` and removes nothing; a plain doctor run never purges. Each purge is audited (`maintenance.purge_seal`).
   A failed directory removal reports `archiveRemoved: false` (the record is already gone, the directory is inert).
4. CLI: `credmgr doctor --purge-expired-seals` (with `--dry-run` it only lists).

**Tests** (`seal_durable.rs`, each failing with its fix removed): a child created between the sub-node check and the lock is found
and nothing is committed; `node.create` cannot run inside a seal's window and then finds its parent gone; a directory claimed
between a restore's checks and its lock is dropped, not committed twice; `node.set_workdirs` cannot run inside a restore's window;
the purge on day 6, day 8 without the flag, the dry run, the real run, a second run, the id reusable, a restart that verifies, a
non-Admin refused, a locked vault refused, only the expired seal purged.

**Still open (named, not fixed):** hot keys copied without a wipe on a whole-map replace (K-7 known risk 2, unchanged); an
approval is keyed by (node, entry), not by the requesting session (known risk 4).


## ADR-090 · `vault.approval_get`, and `pendingApprovals` in `vault.status`: the person sees what is being asked before deciding

**Context.** ADR-088 let a person decide an agent's waiting request with the unlock factors while the vault stays locked, and left one
thing out: nothing described the request. The person decided by the request id the agent printed; `vault.status` said only
`{locked, initialized}`, so a window could not even know a request was waiting. The front end's report of 2026-10-25 asked for both
(B-1, B-8).

**Decision.**

1. **A 55th op, `vault.approval_get {request?}`**, read-only. With `request` it answers
   `{request, node, entry, nodeLabel, entryName, command, state, expiresIn, requestedAt, nameHidden?, cwd?}`; without it,
   `{pending: [...]}` — every request still waiting (unexpired, undecided), oldest first. `command` is always `entry.reveal` (the only op
   that opens a request). `state` is `pending`, `approved` or `denied` (a decided request is only reachable by its id, and only until the
   requester takes it). An unknown, expired or taken id is `not_found`. `expiresIn` is seconds left; `requestedAt` is Unix seconds.
2. **It works on a locked vault and decrypts nothing.** Names are read from the node registry and the manifest already in memory; no key is
   derived and nothing is staged. A name that is not in memory is `null`, never an error. It does not unlock, and it is not audited as a read of
   anything.
3. **Who may ask.** On an unlocked vault only the owner's login session (`is_owner_session`); anyone else is `capability_not_held`
   (`admin`). A locked vault has no session, so there the answer is the same for any caller on the socket. The request id is not a credential (a decision needs
   the passphrase and, with a gate, the code). **Known risk, named plainly:** the list covers every requester's requests, not only the caller's own, and
   the names come from manifests that stay in memory after a lock. So a same-user process (an agent included) can, on a LOCKED vault, learn which
   nodes and entries other agents are asking for, when, and the node and entry names of nodes that are not private; an unlocked vault refuses the same
   caller (`capability_not_held`), so a locked vault tells it more than an unlocked one. It cannot read a value, decide anything, or see a private
   node's names, and it learns no requester identity (`cwd` is the owner's login only, and a locked vault has no owner login). Accepted for the Lock
   screen's sake; ids only (no names) while locked is a one-line change in `approval_view` if the owner prefers it.
4. **`privateNames`.** The node label and the entry name are withheld (`null`, `nameHidden: true`) from everyone but the owner's login session
   (ADR-083). On a locked vault nobody is that session, so they are always withheld there; the ids remain (`node`, `entry`) and are the opaque
   ones when the node was created that way (ADR-091). The requester's directory (`cwd`) is the owner's only.
5. **`vault.status` gains `pendingApprovals: N`**, the count of requests waiting. A bare number: no node, no entry, no requester. Additive; a
   client that does not read it is unchanged.
6. **CLI.** `credmgr approvals [<request>] [--json]` prints the same; `credmgr status` prints `approvals waiting: N` when N is above 0.
   **MCP.** Not a tool (test I-13 stays green): an agent has no business reading the owner's pending prompts.
7. **Bridge.** `vault_approval_get {request?}` and `AuthState.pendingApprovals` (left out of the page's copy when 0). The Lock screen asks
   `vault.status` every five seconds and, when it is above 0, the list.

**Tests.** `crates/brokerd/tests/part5_approval_get.rs` (7: the count and what it does not name, the locked description with nothing decrypted
and nothing staged, a private node by ids only, the list and expiry, not_found and a decided request, the owner on an unlocked vault and an
agent refused), `crates/cli/tests/cli_parity.rs::approvals_lists_…`, the endpoint matrix (6 rows), the bridge and its drift guards (55/55).

## ADR-091 · The window side of the follow-ups: opaque ids for private nodes, broker warnings shown, the audit id passed through, a reload on every lock the shell sees, and the second factor given on purpose

**Context.** The backend answers of 2026-10-26 named what the window and shell still owed.

**Decision.**

1. **A node whose name is private gets an opaque id.** `privateNames` hides label, entry names and notes, but a node id is chosen by the caller,
   shown to every reader who may list the node, and never changes. When "Hide this node's name from others" is ticked the window creates the node
   with `n_` and twelve random lower-case hex digits (`node.create {id, label}`), not a slug of the label; the label stays what was typed. An
   ordinary node keeps its slug; the first-run project names (no such choice) are unchanged.
2. **The broker's `warnings` are shown.** `entry.create`, `entry.create_batch`, `node.create` and `node.update` answer
   `warnings: ["mixed_script_name"]` for a name that mixes Latin with Greek or Cyrillic. The window says "This name mixes Latin with Greek or
   Cyrillic letters." (a batch: "A name in this batch …") in the same notice as the success, as a warning, without blocking. Only the words the
   window knows are shown; an unknown code is ignored. A pure look-alike twin of an existing name is still refused with `entry_exists`.
3. **The audit id passes through.** `transport.rs::interpret_audited` keeps the envelope's `audit`; `commands::attach_audit` puts it into the
   answer of every changing op (`AUDIT_PASSTHROUGH`: 24 ops) as an additive `audit` member, never over one the broker put there. Reads keep
   their shape. Undo takes the id from the change's own answer; the window no longer reads `audit.tail`, and offers no Undo when the answer has no
   id.
4. **A reload on every lock the shell sees.** After the broker lock, the clipboard clear and the `credmgr://locked` event, the shell reloads the main
   webview (any `LockReason`, hidden window included), leaving the reason in `sessionStorage` so the Lock screen's note survives. JavaScript strings
   cannot be zeroised, so dropping the page is the stronger way to drop typed secrets, reveals and the undo snapshot. **Amended 2026-10-27: the page's
   own locks reload too** (the Lock button, ⌘L and the idle timer all end in the `vault_lock` command). `vault_lock` clears the clipboard, locks the
   broker and, only when the broker answered, schedules `autolock::schedule_page_lock_reload`: 150 ms later the shell evals `location.reload();`
   (a constant, no reason word), so the command's own answer reaches the page first. The model still clears itself at once; the reload is the belt on
   top. The page takes two locks it was not asked for: the idle timer and a hidden window (`visibilitychange`, when auto-lock is on). Their
   sentences ("Locked after N minutes without activity.", "Locked because the window was hidden.") are kept in `sessionStorage['cm.locknote']`
   (`rememberPageLockNote`) and shown once after the reload; `takeReloadLockNote` accepts only those two exact shapes, deletes the key either way, and a
   shell reason wins over it. A user's own lock leaves no note. **Limit:** a lock the *broker* takes by itself (its 30-second idle check) is not seen
   by the shell and does not reload; the page's own timer, which fires first in practice, covers the same case. The reload also drops an open first-run wizard (a shell lock while the recovery code is on
   screen starts the wizard again with a new code): chosen on purpose, because the code is then out of memory and the shell cannot tell the states apart.
5. **The second factor is given on purpose.** The owner's login is exempt from `requireTwoFactor` (B-9), so the S5c dialog never opens from the
   owner's own reveal on a real broker. The chip on a node that asks for a factor is now the action: "Give the second factor" opens the dialog in
   its own wording (for agents and other tools, whole vault, five minutes, ended by a lock or a policy change); the code goes as
   `vault.gate_verify` and nothing is revealed. The refused-call path of the dialog remains for a broker that does ask. Help and the legend say
   the chip protects the node against agents and other callers.
6. **The Lock screen lists the waiting requests** (ADR-090) and asks for a request id only when none is listed. A pick is never changed under the
   person: only an empty pick is filled (when exactly one is waiting); when the picked request goes away the pick, the typed passphrase and the code
   are dropped together. The poll does not run while an unlock or a decision is in flight.
7. **A token-less `vault.status` or `vault.approval_get` is not activity** for the idle clock (`server.rs`): the Lock screen's five-second look must not
   keep a vault that another client unlocked from idle-locking. A live login's status still counts, as before.

**Tests.** Unit (`gates-actions`, `adr090-091`), e2e against the fixture broker (`adr090-091.spec.ts`, `gates.spec.ts`), shell
(`autolock`, `shell_ipc`, `transport`, `commands`, `drift_guards`), and real-daemon journeys (`tests/real/adr090-091.spec.ts`: a private node's
opaque id and an agent that sees no name; a mixed-script name accepted and a look-alike twin refused; the Lock screen's list releasing the
picked request; a gate-enrolled vault, an agent refused, the owner giving the factor on purpose, the agent passing inside the window, a policy
change ending it). **Not proven:** the 300-second clock in a real journey (the broker test proves +60 s and +301 s); the idle timer's own reload in the built
app (⌘L, the Lock button, the hidden-window lock and the shell locks were seen reloading there: `RELEASE_VERIFICATION.md` §12.1).


## ADR-092 · The design drop B20 merged: Doctor's purge is its own row, the factors of a locked decision are never skipped, the live name notice is gone, the second-factor window has a countdown

**Context.** The design side's batch B20 (2026-10-26) answered `BACKEND_ANSWERS_2026-10-26.md`; the questions it left (B-10 to B-14) are answered in `BACKEND_ANSWERS_2026-10-27.md`. Most of the drop's logic is its own mock; the window already works against the real broker. What was merged is the template, the wording and the bindings they need (`design-upstream/PROVENANCE.md`, "Merged 2026-10-26").

**Decision.**

1. **Doctor never purges on its own (B-7).** A plain Doctor run sends no `purgeExpiredSeals`. The separate row "Doctor with purge" (button "Preview purge") does a dry run that lists the seals older than seven days; its Apply keeps the flag and removes the retained originals for good. Before this change the plain Doctor always sent `purgeExpiredSeals:true`, so its Apply destroyed seal originals without a separate ask: a defect, not a design choice.
2. **A decision made while locked always needs the factors (B-10).** The Lock screen's Approve and Deny both stay disabled until the passphrase is typed (and the code, when one is entered). The window does not offer a Deny without factors: the broker would refuse it (`capability_not_held` with no session) and the factors are what authorise it.
3. **The Lock screen panel (S16a)** keeps its radio list and the rules of ADR-091 item 6 and takes the design's layout: a count in the header, an always-visible request-id field ("Not listed? Enter the request id the agent printed."; it shows the id of the pick), the factors and the decision only once a request is chosen, and the line that wrong tries count toward the back-off and a recovery code is not accepted.
4. **The second-factor action and window (S5c, B-11).** The dialog opened from the inspector says "Give second factor" and the design's words (5-minute window, whole vault, every caller, ended by a lock or any node policy change); a refused call keeps its old words. The inspector shows a static "2fa · on reveal" chip, the action "Give second factor" while no window is open, and a countdown chip ("second factor given · m:ss") while one is. The countdown is advisory: it comes from the answer's `expiresIn`, is cleared by a lock, and by this window creating a node with a policy (`node.policy` drops every elevation at the broker). A step-up with no gate enrolled answers `malformed_request`; the window says "No second factor is enrolled, so there is nothing to give." instead of showing a bug.
5. **The live mixed-script notice is gone** from Add entry and Add node (the design's choice, and the broker is the authority): the notice comes from the answer's `warnings` after saving (ADR-091 item 2). The window's own script test was deleted with it.
6. **Not taken:** the helmet CSS line that darkens input borders (`--faint` to `--mute`): an accessibility contrast change that is the owner's call, left as it was. **Decided 2026-11-07 (operator): taken.** The text-input border in `apps/desktop/src/design/app.css` is `--mute`, not `--faint`; other control borders are unchanged. The design's Security-level row and its `entryWarn` banner (ours exists in another form) were not needed.

**Amendment 2026-11-07 (operator decision, recorded in ADR-147).** The open item in item 6 is closed: the input border change `--faint` to `--mute` is **accepted** (the contrast gain is wanted). The CSS change is made on a separate lane; this line only records the decision, and `RELEASE_VERIFICATION.md` §15 row R-10 is where it is looked at in the built app.

**Tests.** Unit (`adr090-091`, `gates-logic`, `errors`, `wp-d`, `compile`, `logic`, `design-audit`), e2e (`adr090-091`, `gates`, `ui-fix`, `wp-b-browse`, `wp-d-ops`) and real-daemon journeys updated to the new words; new: the plain Doctor sends no purge, the purge row does, the countdown appears and ends on a lock, the no-gate step-up is said plainly.


## ADR-093 · Batch 2 of the production plan: a name has a length, a locked decision finishes an interrupted rotation first, and the second factor stays vault-wide for beta.1

**Context.** Three items were left open by the Part 4 wave (`OPEN_WORK_REGISTER.md`, 2026-10-24): a length cap for the input of `canonical_name`, the interrupted-rotation recovery before a decision made with the factors, and the per-node gate secret and elevation.

**Decision.**

1. **Names have a length (`ops.rs`: `ENTRY_NAME_MAX` = 200, `NODE_LABEL_MAX` = 120).** `canonical_name` folds the whole string (NFKC, lower-casing, look-alike fold, repeated to a fixed point) and every create compares it with every name in the node, so an unbounded name was an unbounded amount of work for one request. `entry.create` and each `entry.create_batch` item refuse a name over 200 characters with `malformed_request`, naming the bound (and the item's index in a batch), never the text; the count stops at 201 characters, so a megabyte is not walked to be refused. `node.create` now runs the label through the same validator `node.update` already used (trimmed, 1–120 characters, no control characters): before this, creation took any label while renaming took only a valid one. Existing vaults are unaffected: nothing is re-checked at load. Characters are counted, not bytes. The window caps the Add entry name at 200 and cuts a split paste's first-label name to 190 characters so the numbered repeat (" 2") still fits.
2. **A decision with the factors finishes an interrupted rotation first.** `BrokerState::approval_factors` (the locked Approve/Deny, ADR-088) reads the root wrap like an unlock does, but did not run `recover_interrupted_rotation` first as `unlock_with_passphrase` and `gate_recover` do (ADR-076: "every path about to read a root wrap"). It does now; if recovery fails it answers `internal` and decides nothing (`ApprovalFactorError::RotationRecovery`). The daemon's start-up already recovers, so the case needs a state started over a half-rotated vault without that start-up (a second process, an embedded broker); test `a_decision_with_the_factors_finishes_an_interrupted_rotation_first` fails without the line and passes with it (verified both ways).
3. **The second factor stays vault-wide for 2.0.0-beta.1; the per-node gate secret is deferred to 2.0.0, not dropped.** What exists: one gate (`GATE_SCOPE_VAULT`), one 300-second elevation for every caller, ended by a lock or any node policy change (ADR-085, B-2). A per-node secret would need its own enrolment, recovery codes, replay ledger and window per node, a registry change, and a window design that the front end has not drawn; none of that is needed to make `requireTwoFactor` true today, and a half-built version would be worse than the honest vault-wide one. **Known risk for the stamp:** a code given for one node opens the gate for every node that asks for one, for every caller (agents, MCP, CLI), for up to 300 seconds. *Bound:* the window cannot be extended, ends on a lock or any policy change, and the owner's own login is unaffected; the nodes that ask are the ones the owner marked. *Owner:* the operator. *Resolution path:* the `2.0.0` milestone, issue "per-node second factor"; until then the Help text and the dialog say "whole vault, every caller, 300 s" (ADR-092).

**Not changed.** `canonical_name` itself is a pure function and stays unbounded in the library; the bound is at the broker's doors, where a request enters.

**Tests.** `part4_names.rs` (over the cap refused and exactly 200 accepted; two-byte letters counted as characters; a megabyte refused; the message names the bound and not the text; a batch item refused by index with nothing written; new node labels refused when long, controlled or blank), `rotate_root.rs` (above), `write-logic.test.ts` (the window's 190-character cut).


## ADR-094 · The final audit's two security findings: a reveal never returns a stored 2FA seed, and an approval is taken only by the request it was given for

**Context.** The final adversarial audit of 2.0.0-beta.1 (2026-10-31, `PHASE8_AUDIT_REPORT.md` §7) reproduced two defects on the real daemon. **P0-1:** `entry.reveal` (and so `credmgr get` and the MCP tool `credmgr_get`) returned every field's value, including a stored TOTP seed, to any caller that could reveal the entry; only `totp.seed` was presence-gated, so the documented seed/code split ("a leaked seed is worth forever") did not hold. **P1-1:** a pending approval was keyed by (node, entry) alone, so an approval given for one caller's one-field request was taken, whole, by another caller in reach (a different process in a sub-node's work folder needed no token).

**Decision.**

1. **A seed is never revealed, and there is one seed class.** A field is a seed when its effective type is `totp-seed`: an `otpauth://` URI; upper-case base32 in one piece at 16, 20, 24, 26, 32, 40, 52, 56 or 64 characters; base32 in groups of exactly four split by spaces or dashes, in any case; or a field its owner typed `totp-seed` (any shape). `entry_doc::reveal_json` answers such a field with `value: null` and `redacted: "totp_seed"`, and the single-value shape (`value`) is `null` when that field is the only one returned. This applies to every caller, the owner included: the app never showed a seed ("a code is shown, never copied"), the code comes from `totp.code`, and the seed itself only from `totp.seed`, which needs presence and answers `presence_required` today. Every other field is unchanged. The same class is the one `totp.code` computes from: a field that is not a seed is refused there with "that field is not a TOTP seed; its owner can set its type to totp-seed", so reveal and code can never disagree (the re-verification found they did). **An agent cannot retype a seed away:** `field.update` with a `type` patch on a seed field is refused (`capability_not_held`, Admin) for a caller that is not the owner, so the type cannot be used to turn a withheld seed into a readable value. A seed in a shape that is not recognised (a plain lower-case run, a padded one) is not protected until its owner types it: known risk K-19, issue #40.
2. **An approval is one slot per (node, entry, requester), and it releases only the fields it was asked for.** `PendingApproval` carries an opaque `request_key` built from the scope's node and a digest of its token (never the token); the work folder is deliberately not in it, because a caller reaches any subdirectory of its folder and would mint requesters (and flood the table) at will, and the sorted field ids the request asked for (`None` for all). A second requester makes its own request and is decided on its own. A retry by the same requester may narrow what was approved (the earlier behaviour, kept) but may not widen it: a request that reaches past the approved fields is refused (`malformed_request`, after its field ids are checked) and the approval stays usable by the request it was given for. Two processes with the same node and no token are one requester; that is stated in K-7.
3. **The table is capped.** Requesters are as many as there are tokens and work folders, so the approval table holds at most 512 slots; past that the oldest undecided one is dropped (its requester asks again; nothing is released).

**Not changed.** The lock-epoch check between decide and reveal, 128-bit request ids, and the factor back-off (the audit looked and found no defect).

**Tests.** `field_model.rs` (`a_reveal_never_returns_a_stored_totp_seed`: two-field, one-field and `otpauth` seeds, the code still works; two older tests that used a reveal to prove a seed survived now prove it with `totp.code`); `approval_locked.rs` (`an_approval_is_taken_only_by_the_request_it_was_given_for`: another requester is its own request; a request that reaches past the approved fields is refused and the approval stays); a unit test in `entry_doc.rs`; round 2 (the re-verification): `the_seed_class_is_one_class_and_an_agent_cannot_leave_it` (24- and 52-character and grouped seeds withheld, an agent's retype refused, `totp.code` refuses a non-seed and works once its owner types it), `a_callers_subdirectories_are_one_requester`, and the inference test `totp_seed_shapes_services_display`.

## ADR-095 · A signed, machine-bound, expiring licence for the future; a failed licence never locks the vault; no hosted database of vaults (2026-10-31)

**Context.** The operator (live chat, 2026-10-31) asked for a donation proof whose transaction hash is encrypted and time-bound, a licence tied to the computer and impossible to share or replay, a code that changes over time, a response to tampering, and a decision between our own database and a one-time device-to-device transfer, for a product that is free now and will not be later on every operating system. `ADR-074` (MIT, nothing gated) and `ADR-082` (a static supporter code opens cosmetics) stand for 2.0.x; `ADR-094` (`PRU-1`) already sets personal cross-device sync as the direction.

**Decision.** (Design only; `24_LICENCE_AND_DONATION_PROOF.md`.)

1. **One proof for two products.** The same request/response flow earns a *supporter* token (cosmetics, never gates a feature) now and a *licence* token (entitlements) only from the release where the operator announces paid tiers (2.3 at the earliest). `ADR-074`'s "no licence server, no activation step" is superseded for paid entitlements from that release, and only for them.
2. **Asymmetric, offline-issued, machine-bound, leased.** An Ed25519 token (root key offline, public key in the shell) bound to a machine fingerprint (macOS `IOPlatformUUID`, Windows `MachineGuid`, Linux `/etc/machine-id`, hashed with a fixed label), with `iat/nbf/exp/epoch`; a lease of 35 days (monthly) or 400 (annual, supporter) whose epoch rises each renewal, so the held code changes and an old one lapses. No static code gates anything paid; the `ADR-082` static supporter key is retired when this ships.
3. **The request is sealed and tied to the payment.** An X25519 sealed box carries the fingerprint, a timestamp, a nonce, the chain and the transaction hash, so it is opaque and different every time; an exact amount carrying a per-request tag binds the transaction to the request, because a hash alone is public. A single-use ledger refuses a reused transaction.
4. **A failed or tampered licence turns off the licensed entitlements only. It never locks, refuses or degrades the vault** — unlock, read, write, export and backup always work. (The operator's brief asked for a lock; this departs from it on purpose and states the cost of overruling in §9 of the document.) Rollback of the clock beyond 24 hours, a bad signature, a wrong fingerprint or a state record that fails its seal is `tampered`.
5. **No hosted database of users' vaults.** Device-to-device transfer and the end-to-end-encrypted sync of `PRU-1` are the only designs; a hosted plaintext or server-keyed vault is rejected. Sync may be a paid convenience; it may never be the only way to reach a user's own data.
6. **The check lives in the shell, never in the page or the broker**, and the page learns only a state and a list of entitlements. An optional renewal service holds a 90-day delegate key that can renew, never issue.

**Not decided here.** Prices, tiers, the tamper policy if the operator overrules item 4, and the first paid release; each is the operator's. **Not changed.** Nothing in `2.0.0-beta.1` is gated, no network call is added, `DONATE.md` and `PRIVACY.md` are unchanged until a paid tier ships.

**Evidence.** None built: this is a design record. The attack table is `24_LICENCE_AND_DONATION_PROOF.md §6`.

## ADR-096 · CredMgr is source-available under the FreexStudio Source-Available Licence, not MIT; the repository is the FreeXStudio-Platform organisation's (2026-10-31)

**Context.** `ADR-074` (2026-10-01) chose MIT for everyone. The operator (live chat, 2026-10-31) restated the intent: the source is public so that people can check it is safe, report problems and propose fixes; the FreexStudio team keeps all rights; nobody is approved to copy, change or redistribute the app other than running its current stable version; future versions may not be free. MIT allows copying, forking and selling, so the two cannot both stand, and calling the result "open source" would be untrue. The repository had never been public and no third party had received it under MIT (it was private, forking was off, and nothing was published), so a change costs no one a right they held.

**Decision.**

1. **`ADR-074` is superseded.** The licence is the *FreexStudio Source-Available Licence 1.0* (`LICENSE`, identical in `v1/` and `v2/`; SPDX-style id `LicenseRef-FreexStudio-SA-1.0`). It grants: run the official unmodified current stable release; read, audit and build the unmodified source to check it; one backup copy; report problems and send contributions. It forbids copying, redistribution, forks, modified builds, offering it as a service, removing notices, tampering with licence or integrity mechanisms, and use of the names. Contributions are licensed to FreexStudio (perpetual, sublicensable; the contributor keeps their copyright). Releases to date are free; later versions may be paid or differently licensed, and a version already held keeps its own licence.
2. **It is called "source-available", never "open source"**, in every file, because the licence is not an OSI licence.
3. **Entitlements never lock the vault** (`ADR-095` item 4 stands): a licence term can switch off paid extras, not the user's access to their own data.
4. **The repository lives in `FreeXStudio-Platform/credmgr`** (the FreexStudio enterprise), transferred from `Cryptosours/credmgr` on 2026-10-31. Publication is a separate, later, operator decision and goes through `tools/public-export` into a fresh public repository so that no private history is published.

**Not decided here.** Governing law and venue (a lawyer's call), prices and tiers, the publication date. The licence text is not legal advice and should be reviewed by counsel before the repository goes public.

**Evidence.** `LICENSE`, the manifests (`license-file`), `THIRD_PARTY_NOTICES.md`, `tools/gen_third_party.py`; `corpus_check` clean.

## ADR-097 · V1 vault import is a one-way, read-only copy run by the owner; the doctor will gain a hygiene scan (2026-10-31)

**Context.** V2 deliberately has no import from V1 (`11_MIGRATION.md`), and the owner of a 224-entry live V1 vault wants to start using V2. An audit of that vault (read-only, in memory, names only) found what a hygiene pass should catch: numbered wallet series filed as separate entries (five, three and two wallets) and a `seedPhrase` field that holds a note, not a seed (a first reading took the repeated note for one shared seed: a seed is only a seed when it is 12 or more alphabetic words); the same private key under two names; the same API key under two names (one misspelt); a database password stored twice; credential-shaped duplicates of public hosts and usernames; public configuration (URLs, IDs, ports) and free-text network notes filed as credentials; two index rows with no value; 115 of 131 `global` entries with no project prefix.

**Decision.**

1. **`tools/v1-to-v2/migrate.js` is the import.** It reads V1 through V1's own library, writes into an *unlocked* V2 through the V2 CLI, one project to one node, one V1 field to one V2 field, never prints a value, verifies each copy by hash in memory, is idempotent, skips entries that name an operator-sealed target unless told otherwise, and never writes to V1. Dry run is the default.
2. **V1 stays the system of record** until the owner has used V2 for a while; the copy is not a migration of authority.
3. **The doctor gets a hygiene scan (planned, `25_VAULT_HYGIENE.md`).** Inside the broker, over unlocked nodes only, it reports names and reasons, never values: exact duplicate secrets, wallets that share a seed (proposed as one wallet with accounts and derivation paths), near-duplicate names, public configuration filed as secrets, empty and placeholder values, oversized notes, retired or expired entries, and index/value drift. It proposes and the user applies; it never deletes on its own.

**Not changed.** The broker's operation set, the error codes and the MCP tool list (`corpus_check` counts stay).

**Evidence.** `tools/v1-to-v2/migrate.js` run against a synthetic V1 vault and a throwaway V2: copied, verified by hash, idempotent on a second run, V1 mtime unchanged. The scan itself is not built.


## ADR-140 · Per-node security levels: Open, Guarded (default), Sealed — enforced where an agent's request is decided (2026-11-06)

**Context.** `17_AIRLOCK_AND_LLM.md §2` specified one setting with three levels and marked all of it `planned`: no `SecurityLevel` existed anywhere in `v2/crates`. Every agent reveal on an unlocked vault was answered at once, whatever the entry's sensitivity; approval-on-demand (ADR-042, ADR-088) existed only for a locked vault or node.

**Decision.**

1. **A field on the node's policy:** `securityLevel` ∈ `open` · `guarded` · `sealed`, in `NodePolicy` (`credmgr_core::registry::SecurityLevel`). A registry written before the field existed reads as `guarded`; so does every new node. It is reported by `graph.snapshot` (`securityLevel` on every row, including a hidden-name row) and by `whoami` (`level`, the caller's own node).
2. **It binds agents, never the owner.** The level is applied only to a scope whose origin is `Agent` (a cwd-scoped caller or an agent token). The owner's login, the CLI session and the native shell are not held by it. The level of the *target* node applies, so a cross-node read through a grant is held by the level of the node being read.
3. **Reveal.** `entry.reveal`: Open never waits; Guarded waits for the owner when the entry's sensitivity (read from the plaintext manifest projection, no key needed) is `high` or `critical`; Sealed always waits. "Waits" is the existing one-tap path: `reveal_via_approval` (one request per node, entry and requester; decided with `vault.approval_decide` by the owner, or with the unlock factors while the vault is locked, ADR-088; the answer is staged when approved and handed over once). No new operation and no new error code: the agent sees `approval_pending`, `approval_denied` and the answer it always saw.
4. **Create.** Open and Guarded: as before (a locked node's write already lands in the tray, ADR-069). Sealed: an agent's `entry.create` and every item of `entry.create_batch` land in the held-entry tray even on an unlocked node; the owner accepts or discards (`vault.pending_accept`, `vault.pending_discard`). The tray is the approval of an add.
5. **Change and remove (a deliberate narrowing of the §2 table).** The table said an agent's update on a Sealed node waits for approval. There is no staging for a proposed *edit* (approvals stage a revealed value, trays stage a sealed new entry), and building one would be a second approval mechanism. On a Sealed node an agent's `entry.update`, `entry.rotate`, the four `field.*` operations, `entry.remove`, `entry.restore` and `entry.undo` are refused with `node_access_denied`, rule `L1`, whose remedy says what the owner can do (make the change, or lower the level). The owner makes the change; nothing is lost that a prompt would have saved.
6. **`totp.code` on a Sealed node** is refused to an agent with rule `L1`. The approval path returns the entry's document, and the seed is in it; routing `totp.code` through approval would hand out the seed (the reason `totp.code` never used the locked-vault approval path, `07 §6`). On Guarded and Open an agent gets the current six digits as before.
7. **Lowering the level widens what an agent may do, so it is presence-gated like the other widening policy changes** (`PolicyPatch::widens_reach`, ADR-071/ADR-095): Open < Guarded < Sealed, and a change to a lower one answers `presence_required` until the user's finger proves it. Raising is not gated. A level can be set to the value it already has.
8. **CLI:** `credmgr node policy <id> --reason "…" --security-level open|guarded|sealed`; `credmgr whoami` prints the level. *(Amended by ADR-152, 2026-11-08: users see this level as **Strict**; the stored and wire value stays `sealed`, and the CLI also accepts `strict`.)* **App:** the node inspector's "agents here" control (Open / Guarded / Sealed with the consequence in words under it); lowering shows the Touch ID notice when presence is missing.

**What no level changes** (as `17 §2`): cross-node isolation, orphan sealing, the human-only nature of grants. Nor does a level change the two-factor gate (`requireTwoFactor`, ADR-085), which still applies on top.

**Behaviour change, stated.** Because Guarded is the default and an absent field reads as Guarded, an existing vault's agents now wait for the owner when they reveal a `high` or `critical` entry. That is the default the design always specified; before this ADR it was simply not enforced. A user who wants the old behaviour sets the node to Open (a Touch ID step).

**Alternatives rejected.** A vault-wide level: a wallet node must be able to sit at Sealed while the rest is Guarded (`17 §2`), and one switch hides which node is exposed; a vault-wide default for *new* nodes is not built (new nodes are Guarded). Staging an agent's edit for approval: see 5. A new error code for "this node is sealed": the existing `node_access_denied` already carries a rule and a remedy, and a client written against it keeps working.

**Not changed.** The broker's operation set (no new op), the error codes (25), the MCP tool list (15). `whoami` and `graph.snapshot` gain one additive key each.

**Tests.** `crates/brokerd/tests/security_levels.rs` (10: default and reporting, Guarded waits for high and not for low and releases once, Open never waits and Sealed always waits, the owner is never held, Sealed holds a create in the tray and refuses update, rotate and remove with rule L1, Open and Guarded write directly, Sealed gives no TOTP code, raising is free and lowering needs presence, a bad level is malformed, an old registry reads as Guarded); `crates/core` unit tests; `tests/e2e/agents.spec.ts` (the inspector control, a raise, a refused lowering).

## ADR-141 · Agent clients are wired by pure text in `credmgr-core`: `credmgr mcp --print-config` and five named clients plus a generic one (2026-11-06)

**Context.** `17 §4` described how CredMgr would find a coding assistant's MCP configuration and add the one `credmgr` entry; `10 §3.4` said `credmgr mcp --print-config` would emit the snippet; none existed (`cmd_mcp()` took no arguments).

**Decision.**

1. **`credmgr_core::agentcfg` holds every decision and does no I/O** (`crates/core` stays pure): the client matrix, the entry as each client reads it, the splice, the diff, the Vault Protocol prompt and the `CREDMGR.md` text. The CLI and the desktop shell read and write the files; both call the same functions, so a person sees the same change from either.
2. **Clients (macOS, the platform in scope for 2.0.0):** Claude Code (`~/.claude.json`, `mcpServers`), Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`), Cursor (`~/.cursor/mcp.json`), VS Code and Copilot (`~/Library/Application Support/Code/User/mcp.json`, top-level `servers`, with `"type": "stdio"`), Windsurf (`~/.codeium/windsurf/mcp_config.json`), and a generic `mcpServers` object for anything else. **Not included:** Zed (its `context_servers` shape changed between releases and was not verifiable here) and ChatGPT Desktop (it has no local stdio configuration to write; the prompt, ADR-143, is its route). Adding either is a new row in the matrix.
3. **`credmgr mcp --print-config [<client>] [--binary <abs path>]`** prints the exact configuration on stdout and nothing else (for a pipe or a paste); the hint goes to stderr. For Claude Code it also prints the one-line alternative, `claude mcp add --scope user credmgr -- <binary> mcp`. It reads and writes no file and starts no server.
4. **The splice preserves the file.** The new member is inserted as text into the object that holds the servers; every other byte of the file (key order, spacing, other servers) is unchanged. The result is re-parsed and compared with the original document plus exactly that one entry; if it does not match, nothing is offered for writing. A file that is not valid JSON (a comment, a trailing comma) is refused and shown, never rewritten. A different `credmgr` entry already present is never replaced.
5. **The binary path is absolute** (`--binary`, else this executable; the app searches `CREDMGR_BIN`, its own folder, `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`, `~/.cargo/bin` and `PATH`). A relative path is refused: an agent client starts the server from its own working folder.

**Tests.** `crates/core/src/agentcfg.rs` (16, in-module: fresh file, VS Code shape, byte-for-byte preservation, missing and empty containers, idempotence, a different entry is not replaced, invalid JSON refused, scanner against strings that look like JSON, escaping, disconnect in every position, connect-then-disconnect restores the document, the diff, Claude Code is shown and never written, names parse, the prompt carries names and the level and no value); `crates/cli/src/agent.rs` (4).

## ADR-142 · Connecting writes another application's file only on an explicit click or flag, after the diff, with a backup, and never to Claude Code's state file (2026-11-06)

**Context.** `17 §4.1` and `AR-11`: writing another application's configuration could corrupt it. The brief for this lane adds: never silently.

**Decision.** `credmgr agent connect|disconnect <client>` and the app's Settings → Agents obey one procedure:

1. **Read and plan; write nothing.** The path, the diff (two lines of context) and the backup name are shown. The app returns a *token* with the plan; `agent_apply` recomputes the plan and writes only if the token still matches, so a file that changed after the diff was drawn is not written (`agent_changed`).
2. **Consent is an act:** the CLI needs `--yes` or a `y` typed at a terminal (a non-terminal without `--yes` refuses); the app needs the *Write this change* button of the diff dialog. Nothing runs at startup, on a timer or from the page.
3. **Back up, write through a temporary file and a rename (fsync before), restore the permission bits, read back and compare.** The copy is `<file>.credmgr-backup-<UTC time>` beside the original. A read-back mismatch is reported with the backup's path.
4. **Only the `credmgr` entry changes.** Disconnect removes only that key, and only if present.
5. **`~/.claude.json` is never written.** It is the live state of a running Claude Code (history, per-project settings, caches) that the client rewrites itself; an outside edit races with it. For Claude Code the app and the CLI show the JSON and the `claude mcp add` command and offer *Copy*; `connect` and `disconnect` refuse and print the command.
6. **No audit record.** A connect is a file written by the owner's own process, not a vault decision, and the broker must not hold write access to other applications' files (ADR-146). The backup beside the file is the trail, and undo is *Disconnect* (or restoring the backup).

**Tests.** `crates/cli/src/agent.rs::a_write_keeps_a_backup_and_reads_back`; `apps/desktop/src-tauri/src/agents.rs` (the token changes with either side, Claude Code is never planned for writing); `tests/e2e/agents.spec.ts` (listing, copying writes nothing, Connect shows the change and Cancel writes nothing and Write writes once with the token, a moved file is not written).

## ADR-143 · Settings → Agents, the vault prompt and `CREDMGR.md` (2026-11-06)

**Context.** `17 §3`–`§6` showed a *Settings → LLM Integration* screen, `credmgr prompt`, a `CREDMGR.md` per node work folder and `docs/AGENT_CONTRACT.md`, all `planned`; the beta.1 scope cut had removed the Agents section from the app.

**Decision.**

1. **Settings → Agents** lists the five clients with their state (`not found`, `not connected`, `connected`, `different entry`, `unreadable`) from a file-existence and parse check, never a process scan; *Copy configuration* (Claude Code: *Copy command*) per client; *Connect…* / *Disconnect…* open the diff dialog (ADR-142); *Any other assistant* copies the generic JSON; *The vault prompt* copies the Vault Protocol prompt or the `CREDMGR.md` text for the selected node. If the `credmgr` binary is not found the section says so.
2. **Five shell commands, none a broker op:** `agent_detect`, `agent_snippet`, `agent_plan`, `agent_apply`, `agent_prompt` (`src-tauri/src/agents.rs`), listed in `SHELL_COMMANDS` and held to `bridge.ts` and `generate_handler!` by the existing drift guards; three new bridge-local codes (`agent_refused`, `agent_changed`, `agent_write_failed`). The page copies through the shell's `copy_text`, never the clipboard API.
3. **`credmgr prompt [--node <id>] [--json]`** prints the §5.2 prompt filled from the live vault: the node, the nodes it reaches (itself and its ancestors; grants are not listed), the node's level. Names and structure only; the same function the app calls. **`credmgr agent init [--node <id>] [--dir <path>] [--yes]`** writes `CREDMGR.md` into a work folder; an existing file is shown as a diff and replaced only with `--yes` or a `y`. The file says it holds no secret.
4. **`v2/docs/AGENT_CONTRACT.md`** is the agent-facing contract in the repository: what an agent can and cannot do, the refusals and what each means, per level.
5. **The shell may link `credmgr_core::agentcfg`** (pure text) in addition to `parser`, `fields` and `inference`; `tests/fields_preview.rs` keeps the allow-list, now four modules.

**Tests.** `apps/desktop/tests/e2e/agents.spec.ts` (6 specs × 2 engines); `tests/fixtures/broker/admin.js` models the shell commands and `tests/unit/fixture-shape.test.ts` holds them to `bridge.ts`.

## ADR-144 · Machine lock: the smallest safe version is defined here and is NOT built in this change (2026-11-06)

**Context.** V1 bound the vault key to a hardware fingerprint and asked for the recovery code when the fingerprint changed (`05` stolen-laptop row: "machine-lock helps"; `10 §2.2`: `keystore.status|bind|unbind`; register B7). V2's docs describe it only as "generalised to the platform keystore". On macOS two things exist: the passphrase wrap (`root.wrap.pass`, openable on any computer that has a copy of the vault folder) and, since the presence work, the Touch ID device wrap (`root.wrap.se`, openable only on the Mac that made it).

**What a machine lock must mean to be honest.** It must change what a *copy of the vault folder* can do: with it on, the passphrase alone must not open a copy on another computer. A check in the daemon that merely refuses would be a speed bump (anyone with the folder runs their own daemon), the failure `07`/K-5 already names for two-factor ("guards the door, not the safe"). So the lock has to be cryptographic: `root.wrap.pass` is sealed a second time under a 256-bit device key kept outside the vault folder.

**The smallest safe version (defined, not built).**
1. A device key `<state>/machine/lock.key` (random, mode 0600). On a Mac with a Secure Enclave it should be a key sealed to the chip; a file in the state directory is the fallback and protects against a copied *folder* (a synced or backed-up vault) but not a stolen Mac, whose disk holds both (FileVault is the answer to that).
2. `root.wrap.pass` becomes `magic ‖ key id ‖ nonce ‖ AEAD(device key, plain wrap)`, so "bound" is a property of the file itself and cannot disagree with a flag. Rotation re-seals it; a backup keeps it sealed.
3. `keystore.status`, `keystore.bind`, `keystore.unbind` (bind is free; unbind removes a protection and needs presence), and an honest tier line in Security.
4. **A recovery-code unlock.** V2 has none today: the recovery code is used only to reset the second factor together with the passphrase (`vault.gate_recover`). Without a way to open the vault from the recovery code alone, a lost device key (a reinstalled Mac, a wiped state directory) would make the vault permanently unopenable while the recovery code sits in a drawer. The lock must not ship without it: `vault.unlock` with `method: "recovery"`, through the same second-factor gate as the others.

**Why it is not built here.** Items 2 and 4 change how the root key is opened, in the same code that rotation, backup and the second factor depend on, and a mistake there locks an owner out of the vault. That is a security-critical change that wants its own audit, its own failure-injection tests and the recovery-code unlock built first, not a late addition to a lane whose other work is already large. Nothing in this change depends on it; the Touch ID device wrap already gives a Mac-bound way in. **Tracked** as the `keystore.*` work, **moved to the `2.1` line by ADR-147 (2026-11-07)**, it was the `2.0.0` milestone before; `18_ENDPOINT_INDEX.md` keeps the three `keystore.*` rows `planned` and `16 §3` keeps its disclosure unchanged.

## ADR-145 · Duress code: dropped (2026-11-06)

**Context.** V1's manual and the design's handoff notes asked for an opt-in duress code that "wipes local keys, audited". The brief for this lane allowed a second passphrase that opens a decoy or limited view, but only if it could be done without weakening the real unlock.

**Decision: dropped, not deferred.**

1. **A wipe is an irreversible destruction triggered by typing a string.** It is exactly the action the rest of the design refuses to make easy (seal not delete, a seven-day restore window, ADR-007), it can be triggered by accident or by a child at the keyboard, and the thing it is meant to protect against (coercion) is not changed by it: the person coerced may be made to hand over the recovery code or a backup. No audit line restores a wiped vault.
2. **A decoy view cannot be done without weakening the real unlock.** A second passphrase must open a second, different vault. The broker holds one vault; a second would need its own registry, manifests and root key, a switch inside the daemon between two states, and every unlock would have to try two Argon2id derivations (256 MiB each), so unlocking is slower and the *existence* of the second derivation is measurable in time. The decoy's files would sit in the vault folder, so anyone with the folder sees that a duress code exists; the property that makes a duress code worth having, deniability, is not available on a disk that can be listed.
3. **It adds a code path that decides which vault is real.** Every bug there is either a lockout or a leak.

**Consequence.** No duress operation, setting or screen; `09`, `18` and the manual say "not part of CredMgr" rather than `planned`. What does protect a coerced or stolen device: the idle and sleep locks, Touch ID presence on the sensitive operations (ADR-095), per-node Sealed (ADR-140), per-node locks, and a long passphrase.

## ADR-146 · The `llm.*` broker operations are dropped; the wiring lives in the CLI and the app, where the files are (2026-11-06)

**Context.** `10 §4.3` and `18` planned four operations, `llm.detect`, `llm.connect`, `llm.disconnect` and `llm.prompt`, "so that a config change will be recorded in the audit log like any other decision". The brief asked: build only what the airlock rules allow; if the family does not fit, drop it by ADR and say which doc lines change.

**Decision: the family is dropped.**

1. **The broker is the vault.** Invariants A-1…A-6 describe a process that only answers requests about the vault. `llm.connect` would have the broker open, copy and rewrite `~/.cursor/mcp.json` and the like: a vault process with write access to other applications' files, outside the vault folder, at the request of whoever may call the op. The airlock's one door is *inward*; this would open a second, outward one, and a bug in it is the daemon writing an attacker-chosen path.
2. **Everything these ops needed is already available to the human's own process.** The CLI and the app run as the user, can read and write those files, and need only node names and the node's level, which `whoami` and `graph.snapshot` already give (ADR-140). `llm.prompt` returns text built from names; building it in `credmgr-core` (ADR-141) gives the CLI and the app one implementation without a socket round trip.
3. **No agent can reach any of it.** An op family in the broker is reachable from an agent scope unless every op carries a human-only check, and the MCP registry test (I-13) would have to keep proving that none is exposed. With no op there is nothing to expose.
4. **The audit-log argument does not hold.** A connect is a file written beside a backup, not a decision about vault data; the audit log answers "who asked for what value or change in the vault". The trail is the backup file and the diff the person saw (ADR-142).

**Doc lines that change.** `10_API_AND_MCP.md`: the §2.2 rows for `credmgr llm detect|connect` and `credmgr prompt`, §3.4 (rewritten to the built state), the `llm.*` row of §4.3 (deleted; the section's count 28 becomes 24), the shell-command row `llm_detect()/llm_connect()`; `17_AIRLOCK_AND_LLM.md`: §4.1, §4.2's last row, §4.3, §5.1, §5.3, §6, §7 and the verification line; `18_ENDPOINT_INDEX.md`: the `llm.*` row, and the list of namespaces that are zero built (`llm.*` leaves it, so 15 of the 24 remaining planned operations sit behind namespaces not started); `09_UI_UX_SPEC.md` and `PRODUCTION_PLAN.md` where they list `llm.*`.

**What was built instead:** ADR-141, ADR-142, ADR-143. **Not changed:** the broker's operation set, the error codes, the MCP tool list.

## ADR-110 · A `privateNames` node does not tell a guesser that a name exists: a colliding create succeeds under a free name (issue #35, 2026-11-06)

**Context.** The final audit (P2-4, K-17) reproduced that on a node with `privateNames`, `entry.list` and search hide names but an agent with the default `create` capability learns whether a guessed name exists: `entry.create {name:"STRIPE_LIVE_KEY"}` answered `entry_exists`, case- and look-alike-insensitively, and a miss left an entry behind. `ADR-083` listed the surfaces that withhold names and did not list this one.

**Decision.** For a caller that `hides_names` (everyone but the owner's login) on a `privateNames` node, `entry.create` and every item of `entry.create_batch` treat a colliding name like a free one: the entry is created under a free name made from the typed name (`name (2)`, `name (3)`, … checked against the manifest and the locked-write tray, base cut to stay within the 200-character cap). The reply has the same shape for both outcomes and does not echo the stored or the assigned name. The owner's login and every node without `privateNames` keep `entry_exists`. Rejected: refusing every non-owner create on such a node (it would stop agents writing into a locked vault, which `ADR-023` allows and the tray exists for) and refusing with one answer for both (it still separates a hit from a miss by whether anything was stored).

**Consequence.** An agent can no longer test names; it can still add entries, as before, which the owner sees as `name (2)` beside the original and can remove. `entry.restore --mode replace` already withheld the removed entry's name (ADR-083).

**Tests.** `part4_private_names.rs`: `an_agents_create_does_not_tell_a_hidden_name_from_a_free_one` (exact and other-case guesses, same reply shape, twins visible to the owner, batch), `the_owner_and_an_open_node_still_get_entry_exists`.

## ADR-111 · A field that could be a TOTP seed but is not typed as one is named to its owner (issue #40, K-19, 2026-11-06)

**Context.** `ADR-094` withholds a stored seed from every reveal and computes codes only from fields that are seeds; a seed in a shape the inference cannot tell from a word (a plain lower-case run, a padded one) is text until its owner types it `totp-seed`, so an agent that may reveal the entry can read it. Nothing told the owner.

**Decision.** `credmgr_core::inference::looks_like_possible_totp_seed(label, value)` is true for a value that is not already a seed or a recovery phrase and is one base32-alphabet run of 16-128 characters (padding, and spaces or dashes between groups of exactly four, ignored) that mixes letters with at least one of the digits 2-7, or whose label names a second factor (`2fa`, `totp`, `otp`, `authenticator`, `mfa`, `two-factor`, `seed`). `fields::possible_totp_seed(field)` adds: the field has no type override (an owner who typed it, to anything, has answered). The broker reports it: `possibleSeedFields` (field ids) and the `possible_totp_seed` warning in the reply to every write that returns a document (`entry.create`, `entry.create_batch` per item, `entry.update`, `entry.rotate`, the `field.*` ops), and `possibleSeed: true` on the `entry.get` field row. The CLI prints a warning on stderr after `set`, `field add`, `rotate` and `import`, names `credmgr field set <name> --field-id <id> --type totp-seed`, and - only when stderr and `/dev/tty` are a terminal and `CREDMGR_NO_PROMPT` is unset - asks "Type it as a 2FA seed now?" and does it on `y`. The window's use of the same fields is the UI lane's.

**Not decided here.** It is a hint and never blocks or changes a field; a seed the heuristic misses (an all-letter lower-case run under a neutral label) stays text until typed. Over-inclusion costs a dismissible hint; a miss keeps the risk `K-19` already records.

**Tests.** `possible_seed_hint.rs` (names the field on create, update, rotate, field add and batch; `entry.get` marks it; typing it clears the hint, withholds it from a reveal and makes `totp.code` work; an owner-typed field is never flagged; the two warnings share one list), `inference.rs::a_value_that_could_be_a_seed_is_flagged_but_ordinary_text_is_not`.

## ADR-112 · `credmgr backup` is a complete archive and `credmgr restore` rebuilds the vault from it (issue #36, K-18, 2026-11-06)

**Context.** The audit (P2-5, K-18) read the code: the archive packed entry envelopes, manifests, the registry, root wraps, node keys and the orphan key, and left out notes, sealed-node archives, removed-entry and rotation-history archives, the audit log and the generation counter; nothing shipped read the file back. `ADR-054` called it "restorable with only the passphrase".

**Decision.** (1) The archive is the whole vault: everything under the vault directory except `keys/root.wrap.se`, `run/`, `backups/`, `rotation-pending/`, dot files and links, restricted to the known top-level names, plus `vaultGeneration.counter` from the state directory under `_state/` and a manifest `_archive/manifest.json` (`{format, version: 2, files, stateFiles}`) so a restore can tell a truncated archive from a complete one. A backup is refused while a root-key rotation is half finished. (2) `credmgr restore <archive> [--to <dir>] [--state-dir <dir>]` is offline: it decrypts with the backup passphrase (stdin) and calls `store::backup::restore_bundle`, which validates everything before writing, stages beside the target and renames into place; the target must be absent or empty and outside a git working tree; a restore never merges or overwrites. (3) The counter is written only into a state directory that has none (restoring an old directory must not lower rollback protection); an existing counter is kept, and an archive older than it is refused at unlock as rolled back. (4) A version-1 archive still restores, with a note that it never held the extra content.

**Rejected.** Restoring through the broker (a fresh directory has none, and a restore into a live vault is exactly the merge to avoid); lowering or deleting an existing counter to make an old archive open (it is the rollback defence); keeping the archive incomplete and rewording `ADR-054` (the issue offered it; a backup that cannot be restored is not a backup).

**Tests.** `backup_restore.rs` (a vault holding a note, a sealed node, a removed entry, rotation history and an audit log is backed up through the op and restored into a fresh vault and state directory: the tree is byte-identical, the counter is the source's, the new broker unlocks and `maintenance.verify` passes, every entry reveals, the note reads, the rotation is undone from history, the removed entry and the sealed node restore; a wrong passphrase, a damaged archive and a used target restore nothing; an old archive beside a newer counter is refused as rolled back), `backup.rs` unit tests (selection, manifest, unsafe and unknown paths, a manifest that disagrees, a version-1 archive, file modes), `crates/cli/tests/restore.rs`.

## ADR-113 · An authenticator code is not a command-line argument (issue #39, 2026-11-06)

**Context.** `credmgr approve <request> --code <n>` and `credmgr gate verify <code>` took the code as an argument, visible to same-user processes in `ps` while the command runs; `SECURITY.md` counts a secret in argv as in scope. Bound: the code is single-use and worthless after about ninety seconds, and the passphrase is still needed.

**Decision.** The code comes from a prompt (stderr, when stdin is a terminal) or from stdin. `credmgr gate verify` reads one line. `credmgr approve` reads the passphrase from the first stdin line and, when two-factor is on, the code from the second; at a terminal it asks for the code after the broker answers `two_factor_required`. The argument survives only as `--code-on-argv <n>` on both, named so that its cost is in the name and documented in `credmgr help` (visible to `ps`); the positional `gate verify <code>` and the old `--code` are refused (the first with an explanation, the second as an unknown option) and nothing is sent. `no_secret_in_argv.rs` lists `--code-on-argv` with its reason, so a future flag still has to be added on purpose.

**Tests.** `code_not_on_argv.rs` (a scripted stand-in for `credmgrd` records exactly what the binary sends: the code arrives from stdin, trimmed; an empty line sends nothing; the positional form is refused and not echoed; the flag form works; `approve` splits the two stdin lines and explains a missing second one without advising argv), `no_secret_in_argv.rs`, `cli_parity.rs`, `scripts/e2e-journey.sh` (feeds the code on stdin).

## ADR-114 · `release.sh --verify` reads the build stamp, the minimum macOS version and the packaged documents from the bytes (issue #38, 2026-11-06)

**Context.** `--verify` printed ALL PASSED on a tarball whose RELEASE.md and CHANGELOG.md said the CLI needs macOS 27.2 while the binaries said 13.1: without `--run-binaries` it only noted the commit and dirty stamp, never read `LC_BUILD_VERSION`, and never compared the packaged documents with the commit.

**Decision.** (1) `crates/cli/build.rs` and `crates/brokerd/build.rs` turn `CREDMGR_BUILD_COMMIT` and `CREDMGR_BUILD_DIRTY` into one constant `credmgr-build-stamp:v1:commit=<hex|none>:dirty=<0|1>`; `--version` is parsed from it, and it is kept whole in the binary (`black_box`). (2) The verifier finds that stamp in each shipped binary's bytes with no execution: exactly one, a real commit, the same commit in both binaries, equal to `--expect-commit` when given, and a dirty stamp is a failure unless `--allow-dev-build`. (3) It parses the Mach-O load commands itself (thin or fat; `LC_BUILD_VERSION` and `LC_VERSION_MIN_MACOSX`), on any host, and fails a binary whose minimum macOS version is above `RL_MAX_MINOS` (13.1, the app's `minimumSystemVersion`) or whose platform is not macOS. (4) It compares each packaged document (RELEASE.md, CHANGELOG.md, SECURITY.md, LICENSE) with the same file at the stamped commit (`git show`), failing on a difference, and notes (does not fail) when the commit is not in the repository the verifier was started from. A dirty `--dev` build with `--allow-dev-build` notes the difference instead.

**Tests.** `scripts/release-selftest.sh` cases `static-control`, `stamp-removed`, `minos-too-high`, `stamp-wrong-commit`, `doc-not-at-commit`, all run without `--run-binaries` and each shown to be refused for its own reason.

## ADR-115 · `graph.snapshot` reports `gate.twofa` from enrolment, not from the policy alone (issue #37, 2026-11-06)

**Context.** The audit (P3-1) reproduced `gate.twofa: "enrolled"` on every node of a vault that never enrolled a second factor, because the default `requireTwoFactor` is `reveal`; the code comment claimed the state was unreachable and the window drew a warning ring for it.

**Decision.** `gate.twofa` is `none` when the node's policy is `never`, or when the vault has no gate at all (the default `reveal` asks for nothing without a confirmed gate - `second_factor_gate` is a no-op then); `enrolled` while `vault.gate_enroll_begin` has run and `vault.gate_enroll_confirm` has not; `required` once the vault gate is confirmed and the policy asks. The comment is rewritten to say so.

**Tests.** `graph_snapshot.rs::gate_twofa_reflects_node_policy_and_the_vault_wide_gates_own_state` now pins all three values on one vault: none, enrolled, required.

## ADR-098 · Touch ID on the Mac: a Secure Enclave key proves presence, the broker checks the proof, and the root key can be sealed to the chip (2026-11-06)

**Context.** Five operations (`audit.get`, `totp.seed`, `node.reparent`, `grant.create`, a registry rebuild), a widening `node.policy`, `maintenance.rotate_root` and the read of a sealed ("orphaned") entry all waited for a "native presence attestation" that no transport could produce, so each answered `presence_required` and did nothing. Issues #18 (Touch ID) and #19 (Secure Enclave tier) were planned behind an Apple Developer ID on the belief that the sensor and the Enclave need a signing team. That belief is wrong for what this product needs: a **non-permanent** Secure Enclave key whose opaque `dataRepresentation` the app stores itself (CryptoKit) works in an ad-hoc-signed, unsigned binary; only the keychain-permanent route fails (`errSecMissingEntitlement`, -34018). Measured on the operator's Mac before building.

**Decision.**

1. **A Swift helper, `credmgr-presence`** (`native/macos/presence`, built with `swiftc`, shipped beside `credmgr`/`credmgrd` and inside `CredMgr.app/Contents/MacOS`), is the only code that touches the Secure Enclave and LocalAuthentication. One JSON request on stdin, one reply on stdout (`probe`, `enroll`, `sign`, `ecdh`). It keeps no state and no secret. A helper process, not FFI, because the workspace forbids `unsafe` and CryptoKit's Enclave types are Swift-only.
2. **Presence is a signature, not a claim.** `presence.challenge {op, params}` returns a single-use 32-byte nonce (60 s, bound to the op and the login session) and the digest to sign: `SHA-256(domain ‖ nonce ‖ op ‖ canonical-JSON(params))` (`credmgr_core::presence`). The Enclave key (access control `userPresence`: Touch ID, or the device password when no biometry is enrolled; never `biometryCurrentSet`, so re-enrolling a finger cannot destroy anything) signs it, which is what prompts the user. The request is repeated with `params.presence = {nonce, signature}`. The broker re-derives the digest from the request it actually received, finds the nonce, checks op and session and expiry, verifies the signature against an **enrolled public key**, and burns the nonce whether or not it verified. Enrolled keys live in `keys/presence.enroll`, HMAC'd under the root key; a file that fails its tag stops the vault opening (never "nothing enrolled"). Agents and fixture tokens can never hold a proof: the gate answers them with the old `presence_required`.
3. **Every gated op executes with a proof.** `audit.get`, `totp.seed` (the seed itself, only here), `node.reparent` (depth and kind follow; cycles and orphan refused), `grant.create`, `node.policy` when it widens reach, `maintenance.rotate_root`, `maintenance.doctor` with `rebuildRegistry` (diff first; `apply: true` writes, then the vault locks itself so the next unlock loads it from disk), and the sealed read (`orphan.list` names only; `orphan.reveal` costs a fresh second factor **and** a proof every time, drops the second-factor window after, and has no CLI command and no MCP tool). Eight new broker ops: `presence.status`, `presence.challenge`, `presence.enrol`, `presence.unenrol`, `device.enrol`, `device.remove`, `orphan.list`, `orphan.reveal` (63 in all), and one new error, `presence_failed` (reasons `not_enrolled`, `expired`, `invalid`, `cancelled`, `locked_out`, `unavailable`).
4. **Touch ID unlock is a second door, not a replacement.** `device.enrol` seals the resident root key to a Secure Enclave key with ECIES (ephemeral P-256 ECDH, HKDF-SHA256, ChaCha20-Poly1305) into `keys/root.wrap.se`; sealing needs only the public key (no prompt) and opening needs the chip, so it works on this Mac only. `vault.unlock {method:"device"}` opens it and then runs the same tail as a passphrase unlock (registry HMAC, rollback counter, second-factor gate). The passphrase and recovery wraps stay. `vault.status` reports `touchIdUnlock` so the Lock screen can offer it. A root-key rotation re-signs the enrolment and re-seals the device wrap to the same Enclave key silently. Neither file is in a backup.
5. **Clients prove for you.** The CLI and the desktop shell answer a `presence_required` themselves (challenge, sign, retry); the page never sees a nonce, digest or signature. With no key on this Mac they hand the original answer through and the screen offers to set Touch ID up. New CLI: `presence status|enrol|unenrol`, `touch-id enable|disable`, `unlock --touch-id`, `node reparent`.
6. **Signing and notarisation are distribution, not capability.** They are still wanted (Gatekeeper), still the operator's account, and still tracked in #28; nothing here waits for them.

**Rejected.** Keychain-permanent Enclave keys (need a team entitlement). Face-ID-style `biometryCurrentSet` (a new fingerprint would orphan the wrapped root key). A broker-side "trust the shell" flag (a same-user process could claim it). Reading presence from `LAContext` alone (a boolean the broker cannot check).

**Not done here.** Windows Hello/TPM and Linux keystores (#29), held back by the operator. A `credmgr` CLI reveal of sealed entries (absent by design). A per-use anti-hammering counter beyond what the Enclave itself enforces.

**Evidence.** `crates/core/src/presence.rs` (digest, verify, ECIES; unit tests), `crates/keystore/src/secure_enclave.rs` and `presence_client.rs` (tests against the real Enclave through the unattended test helper), `crates/store/src/presence_file.rs`, `crates/brokerd/tests/presence.rs` (11 tests: single use, moved params, other session, TTL, lock, tamper, second key needs the first, Touch ID unlock across restart and rotation, every gated op), `scripts/e2e-presence.sh` (real `credmgrd` + `credmgr`), the shell's `tests/` drift guards. The sensor itself (a human finger) is the one thing a script cannot press; the unattended helper stands in for it in tests, and the live check is recorded in `RELEASE_VERIFICATION.md`.

## ADR-130 · `node.rekey`: a new key for a node, every file re-sealed to it, one commit point (2026-11-06)

**Context.** A node's private key opens every envelope sealed to its public key. Nothing could replace it: a key believed exposed, a retired machine, or ordinary hygiene had no remedy short of creating a new node and moving entries by hand (which loses history and the removal archive). Issue #32 and `PRODUCTION_PLAN.md` ("`node.rekey` (4.9; spec first)") asked for the op with the protocol written down before the code.

**Decision.**

1. **The op.** `node.rekey {node}`: owner login only (never an agent), `Admin` on `global` and on the node, the node unlocked, a fresh second factor when a gate is enrolled (`require_fresh_second_factor`), and a presence proof for exactly this request (`presence.challenge`, ADR-095). The second-factor window is dropped on success, so the next rekey costs a code of its own. The `global` node may be re-keyed; `orphan` (a cold key, ADR-079) and a sealed or missing node may not. The op runs under the **exclusive request barrier**, the way `maintenance.rotate_root` does (`server.rs`), so no request reads an envelope between the key swap and the last file install.
2. **What is re-sealed.** Everything sealed to the node's public key: the live entries (`nodes/<id>/entries`), the note (`notes.env`), the retained history of rotated and edited entries (`archive/entry-history/<id>/…`) and the entries removed inside their seven days (`archive/removed-entries/<id>/…`). Each is opened with the old key and sealed to the new one **with the same payload kind and the same node/entry binding**. The digests that describe them change with them: the manifest rows and `notesSha256` (one generation bump), and the two signed records that carry a digest, `removed.json` and the history `.json`, are re-signed under the same root key (`entry_archive::with_sha256`, `rotation_history::with_sha256`; each verifies the record first). A node with entries waiting in the locked-write tray (ADR-069) is **refused**: those envelopes are sealed to the old public key and are in no manifest, so there is nothing to re-seal them against. Accept or discard them first.
3. **The commit protocol** (the registry write is the commit point; the table is in `state/rekey.rs`):

   | step | what | status |
   |---|---|---|
   | K0 | authorise; refuse orphan, sealed, locked, tray-pending; write the vault through; check the manifest on disk is the one the registry binds | — |
   | K1 | new keypair; open and re-seal every file; compute every digest | memory only |
   | K2 | stage in `rekey-pending/<node>/`: the new wrapped key, **copies of the old key file and the old manifest**, the re-sealed files, and a plan sealed under the root key (`seal_under_root`, label per node) listing every file's digest — **the plan is written last** | pre-commit, unread |
   | K3 | memory, persist lock held: the new key becomes the node's key (wrapped, public, hot), rows take their digests | memory |
   | K4 | **commit**: the ordinary write-through (node key files, manifests, then the registry) with the node's `publicKey` in the registry replaced, inside the op | **commit** |
   | K5 | install the staged files over the live ones (idempotent), remove the stage | post-commit |

   **The registry alone says what a stage means.** On every load, after the registry has verified and before any key or manifest is read (`verify_registry_and_rest`), each `rekey-pending/<node>/` is settled: the plan is opened under the root key (a plan that does not authenticate **refuses the load**, it is never trusted); if the registry's `publicKey` for the node is the plan's *new* key the commit happened and the stage is **rolled forward** (every staged file checked against the plan's digest, installed; the new key file written after proving it unwraps to the new public key); if it is the plan's *old* key the commit did not happen and the stage is **rolled back** (the write-through writes the node key file and the manifest *before* the registry, so the staged copies of the old ones are put back; the live envelopes were never touched); if there is no plan, the crash came before K2 finished and the stage is removed; if the registry names neither key the stage is stale and removed. A commit that reports failure without a crash is read off the disk the same way (`registry_file::load`) and either finishes or reverts memory and files in the same process.
4. **Crash table.** Each row is made to happen by stopping the real protocol there (`RekeyFault`, `PersistFault`), dropping the broker and starting a fresh one over the same files: after K2 → old; after the key/manifest writes before the registry → old (rolled back); after the registry before the counter → new; after K4 before any install → new; after the first install → new; a failed (not crashed) commit → old, same process. All five crash rows fail when the recovery call is removed (checked).

**Rejected.** *Re-sealing in place, file by file, then switching the key* — a crash mid-way leaves files only a key the registry no longer names can open. *Writing the new key file only after the registry* — the write-through writes every node's key file first; staging the old key and manifest and deciding by the registry is simpler than a second write path. *Re-keying as part of `maintenance.rotate_root`* — different keys, different blast radius: a root rotation re-wraps node keys and re-signs, it never re-seals an envelope.

**Not changed.** The root key, the other nodes, grants (they are registry facts, not cryptographic), the orphan cold key.

**Known limits.** A rekey cannot make an attacker who already copied the old ciphertext *and* the old wrapped key forget them; it protects what is written afterwards and ends the old key's usefulness against the vault as it is now. Backups made before the rekey still open with the old key and the root key then in force.

**Tests.** `crates/brokerd/tests/rekey.rs` (11): key replaced and every file follows (entries, note, history, removed, digests, signed records) and survives a restart with the removed entry still restorable; `global` yes / orphan, sealed, unknown no; tray-pending refused with nothing changed; the five crash rows plus the in-process failure; tampered plan and tampered staged file refuse the load; the owner/second-factor/presence gates and the spent window (the last runs against the real Secure Enclave helper).

## ADR-131 · Destroy orphans: sealed entries and the material behind them end for good, on purpose (2026-11-06)

**Context.** `node.seal` moves a node's entries to the orphan node (sealed to its cold key) and keeps the originals for seven days (ADR-079); a purge ends the originals but "what the node held stays in `orphan`" (ADR-089). There was no way to ever end the sealed copies themselves.

**Decision.**

1. **The op.** `orphan.destroy {confirm, count, entries?}` — owner login, `Admin`, the confirmation word `destroy-sealed-entries` in `confirm`, **`count`** equal to the number of entries the call would destroy (so a stale list on screen cannot destroy more than it showed), a fresh second factor, a presence proof. `entries` names entry ids; absent means every sealed entry. An unknown id is `not_found`, a wrong word or count is `malformed_request`, and none of those cost the person a prompt (they are checked first). The second-factor window is dropped on success.
2. **What goes.** The chosen orphan manifest rows (one generation bump) and their envelope files; the **seal record** of every sealed node any chosen entry came from (a seal missing some of its entries cannot be restored faithfully, so its record ends — a seal with none of its entries chosen is untouched and stays restorable); the retained originals `archive/<id>/` and the removed-entry and history archives that belonged to that node. "Everything" ends every seal record. The ids become free for new nodes.
3. **Commit protocol** (`state/destroy.rs`): D0 authorise, check the count, write through · D1 write the **journal** `orphan-destroy.pending`, sealed under the root key, listing the envelopes and archive directories · D2 memory (persist lock) · D3 **commit** (write-through with the seal records dropped from the registry) · D4 delete, then the journal. On every load the journal is read and each item is removed **only if the signed state no longer names it** (no orphan row, no seal record), so a journal left by a crash before the commit deletes nothing and is dropped, and one left after the commit finishes the deletion. A journal that does not authenticate is removed unread.
4. **"Permanently."** Files are overwritten with zeros, synced and unlinked. On a copy-on-write or journalled file system that does not reach every old block, and a backup or snapshot made earlier still holds the ciphertext; what the op guarantees is that the vault no longer lists, opens or restores them and that nothing in it can ever bring them back. The cold key stays (other sealed entries may remain).
5. **Audit.** The request is recorded like every op (`orphan.destroy`, allow or deny with the error tag); no entry name or id is written to the detail.

**Rejected.** *A `--force` that skips the count* — the count is the point. *Deleting before the commit* — a crash would lose entries the registry still names. *Per-entry destruction that leaves the seal record* — a restore would then fail half-way; the record ends with its entries.

**Tests.** `crates/brokerd/tests/f1_ops.rs`: refusals without the word, the right count or a real id; partial destroy ends one seal and leaves the other restorable; destroy-all survives a restart and frees the ids; crash after the journal destroys nothing, crash after the commit finishes the deletion; the audit record names the op and no value.

## ADR-132 · Content search: find by what a value contains, answer only ids and names (2026-11-06)

**Context.** `search` matches entry *names*. Finding "which entry holds this host / user / token prefix" meant revealing entries one by one.

**Decision.** `search.content {term, node?}`: server-side, over field **values**, never returning one. CLI: `credmgr search <term> --deep [--node id]` (the flag is `--deep` because the argv guard forbids a flag spelled `--value…` or `--content`).

1. **Answer.** `{results: [{node, id, name}], truncated}` — exactly those three keys per hit; no snippet, no position, no count of matching fields, no field label. A miss is an empty list. A stored 2FA seed field is never matched (the seed/code split, ADR-094, holds for search as for reveal).
2. **Who.** The caller must hold the **`reveal`** capability, and per node `reveal` must resolve to allow; entry-level grants narrow as they do for `search`. A reader who may not see a node's names (`privateNames`, ADR-083 — every agent and MCP caller on a private node) never has that node searched; a node that would ask for a second factor on reveal (ADR-085) is skipped unless the factor is fresh; a locked node is skipped, a locked vault answers `vault_locked`. Because an agent that can reveal can already read a value, content search adds no reach; what it must not add is an oracle across a boundary a reveal could not cross, which the three skips close.
3. **Bounds.** The term is 3–200 characters (a one-letter probe is an enumeration, not a search). At most **12 calls per 60 seconds per caller** (a login by its public session id; anything else by origin and node); a refused call is not counted, the answer is `rate_limited` with the wait. At most 5000 entries are opened per call (`truncated: true` past that).
4. **No MCP tool, no log of the term.** Not on the MCP surface (`credmgr_*` list unchanged, test I-13 untouched); the audit record carries the op name and the node it was narrowed to, never the term.

**Rejected.** *Returning the matching field's label or a snippet* — a label can be a name hidden by ADR-083, and a snippet is a value. *A persistent plaintext index* — the vault holds no plaintext at rest. *No limit* — a reveal-holder could enumerate a value one character at a time; the term floor and the rate window bound it.

**Tests.** `f1_ops.rs`: match by value, case-insensitive, node filter, the exact result keys, no value anywhere in the answer, a 2FA seed unmatched, term bounds; no `reveal` refused, an agent finds on a normal node and not on a private one while the owner still does, the rate window (admits a dozen, refuses with a wait, passes after the window, does not touch another caller); a second-factor node skipped and then searched once the factor is fresh; a locked vault refused.

## ADR-133 · `credmgr export --age`: an age-encrypted archive of a node, built inside the broker, written only to a file (2026-11-06)

**Context.** There was no export at all. The owner asked for an encrypted archive they can open with stock tools and that never touches stdout.

**Decision.**

1. **Op.** `node.export {node, passphrase | recipients}` — owner login, `reveal` on the node, exactly one of a passphrase (12+ characters) or one to sixteen `age1…` recipients, a fresh second factor, a presence proof. The broker builds the plaintext (`credmgr-export` v1: node id and label, every entry with its fields, types, masking and values), encrypts it, and answers only `{archive: base64 ciphertext, entries, omittedSeeds}`; the plaintext is zeroised and never leaves the process. **Stored 2FA seeds are left out** (`value: null, redacted: "totp_seed"`, counted in `omittedSeeds`): an export is not a side door around ADR-094. Notes are not included in this version. The second-factor window is dropped on success.
2. **CLI.** `credmgr export --node X --out FILE --age [--age-recipient age1…]… [--force]`: `--age` is required (an export is always encrypted); the file is written mode `0600` through a temp file and a rename, `--out -` and `/dev/…` are refused, an existing file is not replaced without `--force`; the passphrase is read from stdin twice (never argv — `--age-recipient` is a public key; the argv guard test lists the new flags and what each carries).
3. **The format is age v1, written in `credmgr_core::age_format`, not through the `age` crate.** `age` 0.11 drags the i18n stack (`i18n-embed`, `rust-embed`, `icu`/`tinystr` 0.8, which needs rustc 1.82) that does not build on this workspace's 1.78 pin, and pinning that tree transitive by transitive would be a standing maintenance cost; the deviation is the dependency tree only, not the format. Added: `scrypt` 0.11 (no default features) and `bech32` 0.9, plus `base64` for core. Write side only: header with an `X25519` stanza per recipient or a single `scrypt` stanza (`log2 N` 18, the `age` tool's default; the format forbids mixing), header MAC, 64 KiB ChaCha20-Poly1305 chunks with the final-chunk flag. A low-order recipient key is refused. **Verified against two readers that are not the writer**: an independent decryptor written from the spec (chunk boundaries 0, 1, 65 535, 65 536, 65 537, 131 072; several recipients; a wrong passphrase; a flipped byte anywhere) and **the real `age` 1.3.1 binary** opening files of five sizes (`tests/age_interop.rs`; it passes vacuously when no `age` is installed and says so).

**Rejected.** *Returning plaintext to the CLI to encrypt there* — plaintext would cross the socket and sit in a process the broker does not control. *Including the seeds* — see ADR-094. *Allowing `--out -`* — "never to stdout" is the requirement.

**Tests.** `f1_ops.rs` (shape errors before any prompt; presence and second-factor required each time and spent by the export; ciphertext carries no plaintext; stock `age` opens a recipient export and the JSON holds the value and not the seed); `age_interop.rs` (5); `age_format` unit tests (3); the CLI argv guard and `parse_day` tests.

## ADR-134 · `audit.report`: what happened in a period, without a single value (2026-11-06)

**Decision.** `audit.report {from, to, node?}` — owner login with `Admin`; `from`/`to` are unix seconds, `from < to`, at most 366 days. It reads the monthly audit logs the period touches and answers: record count; decisions (allow/deny/other); counts **by action, by actor, by node** (top 50 each, each with allow/deny); denials (total, by action and the broker's own error tag, the 25 most recent as id/time/actor/action/node/reason); **presence** (uses = allowed records of a presence-gated action or `presence.*`, by op; refused = denials for want of presence); and the **hash chain** of every month the period touches, verified under the root key now (`chain.verified`). Actor strings are the audit's own (`<Origin>:s_<id>`, bearer tokens redacted). Free text a person wrote (`reason: …`) and entry names never appear: a denial's reason is reported only if it is a plain error tag. CLI: `credmgr audit report (--days N | --from YYYY-MM-DD --to YYYY-MM-DD) [--node id] [--json]`. Not an MCP tool.

**Rejected.** *Reusing `audit.tail`'s redaction for agents* — a report is the owner's. *Including `detail`* — it can hold a typed reason.

**Tests.** `f1_ops.rs`: counts by actor/action/decision, the period filter, presence uses and refusals, denial reasons, no free text, a node filter; agent refused, bad ranges refused, an edited log line makes `chain.verified` false.

## ADR-135 · A node's own second factor: built on the scope-keyed gate ADR-064 already had, beside the vault's, which it does not touch (2026-11-06)

**Context.** Issue #16 (ADR-093's known risk): a code given for one node opens the gate for every node that asks for one, for every caller, for 300 seconds, and the owner is never asked. ADR-093 deferred the per-node secret because it needed "its own enrolment, recovery codes, replay ledger and window per node, a registry change, and a window design the front end has not drawn". Measured at the start of this batch: the **first four already exist**. `BrokerState`'s `gate`, `gate_pending`, `gate_replay`, `gate_replay_floor` and `elevations` have always been keyed by a *scope* string (`GATE_SCOPE_VAULT = global`, "a node's own id in the same maps"), `registry.json` already stores one `gate.twofa` per node (sealed under a root-derived key labelled with the scope, re-encoded by every write-through and every root rotation), and load already decodes one per node. What was missing was the broker ops that address a node's scope and the rule that asks for it.

**Decision.**

1. **Four ops, all new, so the vault's own gate (`vault.gate_*`, the unlock, the hand-written `vault_gate_verify` command that holds the session token) is not edited at all**: `node.gate_enroll_begin {node}`, `node.gate_enroll_confirm {node, code}` (ten recovery codes of the node's own, once), `node.gate_verify {node, code}` (a step-up: the node's code, a 300-second window for that node only), `node.gate_remove {node}`. Owner login only, `admin` on the node, not `global` (the vault's gate) and not `orphan`. Replacing a gate in force needs its own code, fresh (ADR-064's rule, per scope). `node.gate_verify` and `node.gate_remove` share the per-uid unlock backoff (`server.rs::is_auth_path`) — a node's code is guessable in exactly the way the vault's is.
2. **The rule** (`ops.rs::second_factor_gate`): where `requireTwoFactor` asks (ADR-085), a node with a confirmed gate of its own is asked for **that** gate's code — **by the owner too**, because the owner's login passed the vault's gate and never this one — and answers `two_factor_required` with `scope` = the node's id. Every other node is asked exactly as before: the vault's gate, the owner exempt. The vault's code never satisfies a gated node; a node's code never satisfies another node or the vault. `requireTwoFactor: never` still asks nothing.
3. **Sensitive ops cost the node's code in addition to the vault's.** `node.rekey`, `node.export` and the removal of the gate itself require the vault's factor fresh (when one is enrolled) **and** the node's own (when it has one), then presence. Every window is dropped on success, so each costs codes of its own.
4. **Removal.** With the node's fresh code and a presence proof; or, when the authenticator is lost, `node.gate_remove {node, passphrase, recoveryCode}` — the vault passphrase and the printed root recovery code together, the last door ADR-064 gave the vault's gate (`gate_recover_scope`, the same function, now parameterised by scope).
5. **Two places a gate could be walked around are closed rather than documented.** `node.seal` refuses a node that has a gate of its own (its restore would bring the node back without the factor; remove the factor first, which is the owner's to do). A locked-vault approval (`reveal_via_approval`, ADR-088) is not opened for such a node — the decision made with the vault's factors cannot ask the node's code — so an agent's `entry.reveal` on it while the vault is locked is `vault_locked`.
6. **Bridge and CLI.** Four table rows (`node_gate_*`), TS functions in `bridge.ts`; CLI `credmgr gate enroll|verify <code>|remove [--last-door] --node <id>` (the same subcommands, about one project).

**What this does not do, and why that is the honest edge.** *The window has no screen yet* — `09_UI_UX_SPEC.md` draws one second-factor dialog; naming the node whose code is asked (the answer's `scope`) and enrolling a node gate in Settings is front-end work the design project has not delivered, so the ops and the bridge exist and the screen is the next batch. *An agent is still one caller class*: a node's code opens that node for every caller (agents, MCP, CLI) for 300 seconds, as the vault's does — the per-node secret narrows **which nodes**, not **which callers**. *A node gate is not a security level* (the issue-#32 item, still `planned`). *The owner who holds both the passphrase and the printed root recovery code can always remove a node gate* — by design; they are the factors that can reset the vault's too.

**Known risk, updated (issue #16).** The vault-wide window remains for every node that has **not** been given its own gate; for those, nothing changed (bound: 300 s, ends on lock or policy change, the owner's login is unaffected). A project the owner marks sensitive can now be given a gate whose code the owner is also asked for and which opens nothing else. *Owner:* the operator. *Resolution path:* the window's dialog (front end), then retire the risk entry.

**Rejected.** *Overloading `vault.gate_enroll_*` / `vault.gate_verify` with a `node` parameter* — it would have put the hand-written, token-capturing `vault_gate_verify` bridge command and the unlock path in the diff for a feature that must not be able to break them. *Making the owner exempt from a node's gate* — then the gate asks nobody who matters. *Asking the node's code in place of the vault's for a node's ops* — a node gate adds a factor; it never removes one.

**Tests.** `crates/brokerd/tests/node_gate.rs` (6): a root-key rotation re-seals the node's gate secret and the same authenticator still works after it; the owner is asked for acme's code and exempt for beta's; the vault's code does not open acme, acme's does not open beta or the vault, a code is spent once, the window is 300 s; the gate and its removal survive a restart and the last door leaves the vault's gate untouched; sealing refused, a locked approval not opened, a rekey asks the node's code before presence; removal needs the fresh code and a presence proof; the op shape errors. The "owner exempt" line was mutated back in and two of the five fail (checked).

## ADR-120 · What is in Orphaned is named in the owner's graph snapshot (2026-11-06)

**Context.** After sealing a node the Orphaned panel said "Nothing is orphaned" and the rail count stayed 0 (C4 F-10, issue #25). `entry.list` on the orphan node is refused to everyone (R0, native + presence only), and `graph.snapshot` leaves that node out for the same reason, so a window that asks only the usual questions has no way to learn what was sealed. Help says names stay visible.

**Decision.** `graph.snapshot` carries `meta.orphaned`: `[{id, name}]` for every item in the orphan manifest, **for the vault owner's own login session with the `admin` capability only** (the person who could list those entries a moment before sealing). Never a value, a label or a field count; absent for an agent, a token or a grantee. The orphan node still is not in the snapshot, and its own list and reveal stay refused (R0). The window takes the Orphaned panel and the rail count from `meta.orphaned`; "open" on an item still asks the broker and is refused for want of presence. A broker that predates this key is read the old way.

**Not changed.** R0; the seal and restore protocols; the 7-day window.

**Evidence.** `crates/brokerd/tests/adr120_orphaned.rs`; `tests/e2e/rc1-ui.spec.ts` (#25); `ui-fix.spec.ts` keeps the old-broker path.

## ADR-121 · Aliases, and a warning for near-duplicate names (2026-11-06)

**Context.** Register Part 4 item 4.7 (issue #20): the exact-name rule (ADR-084) stops `payroll` twice; it does not help the person who wants two names for one entry, or who types `Stripe_Key` beside `stripe-key`.

**Decision.**
1. **An alias is another name for one entry**, in the node's one name space. Stored as `aliases` on the signed manifest row (written only when non-empty, so every older manifest still verifies byte for byte), at most 8, each at most 200 characters, no control characters. Plaintext metadata like the name; hidden from a reader who may not see names (ADR-083).
2. **Uniqueness is the canonical rule across names and aliases.** No alias may equal, canonically, another entry's name or alias, a name in the review tray, or its own entry's name; a new entry, a batch, an import, a restore and an accepted tray entry are refused (`entry_exists`) when they would take a name an alias holds.
3. **`entry.alias {node, entry, generation, aliases}`** sets the whole list. `update` capability on the node, human sessions only (an agent holds no such tool), generation-checked, metadata only: the envelope is neither read nor rewritten. Answers the new generation and a `similar` list when an alias resembles another name.
4. **Lookup.** `search` also matches aliases and says which (`alias`); `entry.list` rows (human sessions) and `entry.get` carry `aliases` when there are any; the CLI resolves a name or an alias.
5. **Near-duplicates are a warning, never a refusal** (`credmgr_core::names::similar_names`): the same letters with other separators or case, or one edit apart (insert, delete, change, swap neighbours) once separators are ignored and both names have five or more letters; names that differ only in trailing digits are a numbered series and never flagged. `entry.similar {node, name, entry?}` answers `{taken, similar:[{id, name, alias?, reason}]}` with the `list` capability; a node that hides its names answers `nameHidden`.
6. **Surfaces.** CLI `credmgr alias`, `credmgr similar`; the window: entry detail "Aliases…" dialog, the hint under the name in Add entry, the notice after saving aliases.

**Not changed.** Aliases are not restored by `entry.restore` from a removal archive (re-add them); an alias change is not undoable and moves the node generation, so a pending `entry.undo` of an earlier field edit answers `conflict`.

**Evidence.** `crates/core/src/names.rs` tests; `crates/brokerd/tests/adr121_122.rs`; `crates/cli/tests/names_cli.rs`; endpoint matrix rows; `tests/e2e/rc1-ui.spec.ts`.

## ADR-122 · The `.env` importer: previewed names, one audited write per entry (2026-11-06)

**Context.** Register Part 4 item 4.8 (issue #21). `credmgr import` (ADR-073) writes a parsed file in one all-or-nothing `entry.create_batch` call: one audit record for the whole batch, and a conflict is reported for the first name only.

**Decision.**
1. **`entry.import_env {node, entries:[{name, value}], dryRun?, onConflict?}`.** The client parses (the same parser everywhere: `credmgr_core::dotenv`, moved from the CLI); the broker takes pairs. `create` capability, 1 to 500 pairs, no other keys.
2. **`dryRun: true` writes nothing** and answers, per pair, `new`, `exists` (a name or alias, or a tray entry), `duplicate` (earlier in the same import), `empty` or `invalid`, with up to three resembling names; plus counts.
3. **The write** makes each `new` pair its own entry (`create_entry`, so a locked node still goes to the tray) and appends one `entry.create` audit record per entry (detail `import-env`, id only) beside the request's own `entry.import_env` record. `onConflict` is `refuse` (default: any conflict writes nothing) or `skip` (conflicts are reported in `skipped`); an invalid name always refuses. Empty values are never entries.
4. **No answer, error or audit record carries a value.** An error names an index.
5. **Shell and window.** `env_preview {text}` is a shell-local command (no broker, no session) running the shared parser; the window's "Import .env…" dialog previews names and conflicts first, holds the pairs only while it is open (wiped on close and on lock), and asks the broker for a dry run before it offers Import. CLI `credmgr import-env <file|-> --node <id> [--dry-run] [--on-conflict refuse|skip]` always previews first. `credmgr import` is unchanged.

**Evidence.** `crates/brokerd/tests/adr121_122.rs`; `crates/cli/tests/names_cli.rs`; `src-tauri/src/env_preview.rs` tests; endpoint matrix rows; `tests/e2e/rc1-ui.spec.ts`. Not exercised in the real-daemon window suite (the Node shim does not port the parser).

## ADR-147 · 2.0.0-rc.1 is what is built today plus Developer ID signing; five items move to 2.1 (2026-11-07)

**Context.** The roadmap in `README.md`, `CHANGELOG.md` and `PRODUCTION_PLAN.md` listed, for `2.0.0-rc.1` and `2.0.0`: the doctor's duplicate and wallet-bundling scan (`docs/25_VAULT_HYGIENE.md`), the V1 copy folded into the app, the machine lock (ADR-144), the Windows and Linux keystores with the Windows named-pipe transport (`docs/16_CROSS_PLATFORM.md`), and the org vault, sync and licensing (`docs/22_ORG_VAULT_SYNC_AND_LICENSING.md`). None of the five exists in the tree; each is large, and the machine lock changes how the root key is opened (ADR-144 said it wants its own audit, its own failure-injection tests and the recovery-code unlock first). The operator decided on 2026-11-07 what ships first.

**Decision (operator, 2026-11-07).**
1. **`2.0.0-rc.1` is what is built on `main` today (2.0.0-beta.2) plus Apple Developer ID signing and notarisation, which only the operator can do.** Before it ships, what remains is: the app wiring of the 2.0.0 broker operations (issue #40), QT-1, a security audit of the changes since beta.1, the built-app re-walk (`RELEASE_VERIFICATION.md` §15), and the operator's own items (the idle and sleep checks #9, the finger checks #18, VoiceOver #22, the relay #12, the local leak-gate blocklist #7, the runner #6, Developer ID).
2. **Moved to `2.1` (not `2.0.0-rc.1`, not `2.0.0`):** (a) the doctor's duplicate and wallet-bundling scan; (b) the V1 to V2 copy inside the app (the read-only copy script `tools/v1-to-v2/migrate.js`, ADR-097, stays and is the supported way); (c) the machine lock, ADR-144 stays "defined, not built"; (d) the Windows and Linux keystores and the named-pipe transport; (e) the org vault, sync and licensing. The order inside `2.1` is not decided here: `README.md` keeps cross-device sync at `2.1.0` and the signed licence at `2.2` until the operator says otherwise.
3. **`2.0.0` is rc.1 after it has had no open P0 or P1** and the operator's items are done; it is macOS on Apple Silicon only, as beta.2 is. No document may promise Windows or Linux for `2.0.0`.
4. **Input border contrast (ADR-092's open item):** `--faint` to `--mute` is accepted. Recorded as an amendment under ADR-092; the CSS is changed on another lane.
5. **`audit-probe.js` from the design project stays out of the public release.** The denylist line `**/design-upstream/*/audit-probe.js` in `tools/public-export/manifest/denylist.txt` is left as it is; the licence question (may it ship under MIT) stays with the operator and is not asked again until he raises it.

**Consequence.** Doc lines changed with this ADR: `README.md` (Roadmap), `v2/README.md`, `v2/CHANGELOG.md` ("Coming next"), `v2/docs/PRODUCTION_PLAN.md`, `OPEN_WORK_REGISTER.md`, `PROJECT_MAP.md`, `docs/history/finish-plan/README.md`; ADR-144 now points here. No code changes. Nothing built is removed, and nothing is promised for a date.

## ADR-148 · Pre-stable security fixes: the final audit's P1/P2 findings, and the cheap P3s (2026-11-07)

**Context.** The final pre-stable audit of `63d5d0a..4bddb37` found five P1, five P2 and a list of P3 findings. Every P1
and P2 was confirmed against the code before it was changed; each has a refusal test that fails with its fix
reverted (checked by reverting all of them at once and running the new tests: twelve failed, the thirteenth is the
P2-5 coverage test) and passes with it. Numbering note: ADR-147 (the rc.1 scope decision) is written on another branch.

### P1-1 · The Touch ID unlock wrap is authenticated, and a rotation only re-seals to an authenticated one

*Finding (confirmed).* `keys/root.wrap.se` was checked only for JSON and `v == 1`; `maintenance.rotate_root` re-sealed
the **new** root key to its `wrapPublic` with no prompt. A process able to write the vault directory could plant its
own P-256 point and receive the next root key. The module comment claiming the AEAD `sealed` blob made a tag
unnecessary was wrong: the blob does not cover `wrapPublic`.

*Decision.* The wrap carries `tag`: HMAC-SHA256 under the root-derived key (label `device-wrap`, the same
`credmgr_core::signing` the registry uses) over canonical JSON of `(v, keystore, wrapBlob, wrapPublic, createdAt)`.
`sealed` is outside the tag (an AEAD blob, rewritten by every rotation). `device.enrol` writes a tagged wrap. A rotation
checks the tag under the **old** root key before anything else (so the refusal is the same with or without the helper)
and writes the re-sealed wrap re-signed under the new one.

*On-disk change and migration.* `root.wrap.se` gains an optional `tag` field; `v` stays `1` (an older daemon ignores the
field). **An untagged wrap (set up before ADR-148) is not trusted for rotation — fail closed by requiring
re-enrolment**: the rotation refuses with "turn Touch ID unlock off and on again". Re-tagging on the next Touch ID unlock
was rejected: opening the wrap proves `wrapBlob` and `sealed` belong to the Enclave key, not that `wrapPublic` does, so a
planted point would be blessed. An untagged wrap still **unlocks** (the Enclave and the registry HMAC decide that); it
only cannot be rotated past. A tag that does not verify refuses the rotation with an integrity message.

*Evidence.* `presence_file.rs::the_device_wrap_tag_binds_the_public_point_to_the_root_key`;
`tests/presence.rs::p1_1_a_planted_touch_id_wrap_never_receives_the_new_root_key` (untagged and forged-tag plants: the
rotation refuses, `root.wrap.pass` and the planted file are unchanged).

### P1-2 · A node's own gate cannot be switched off by `requireTwoFactor: never`

*Finding (confirmed).* `second_factor_gate` asked a node's own code only when the node's `requireTwoFactor` asked;
`node.policy {requireTwoFactor: "never"}` needs only `human_admin_on`, so any owner session skipped ADR-135's gate.

*Decision.* A node with a confirmed gate of its own asks that code before every **reveal** whatever `requireTwoFactor`
says (`always` still adds reads). Removing the gate (`node.gate_remove`: its fresh code and presence, or the last door)
is the only way out.

*Evidence.* `tests/node_gate.rs::p1_2_turning_require_two_factor_off_does_not_skip_a_nodes_own_gate`.

### P1-3 · An agent cannot lower an entry's sensitivity where approval depends on it

*Finding (confirmed).* On a Guarded node an agent could `entry.update` (explicit `sensitivity`, or a value/label change
that re-infers lower), then reveal a former high/critical value without approval. `entry.undo` of the owner's raise had
the same effect.

*Decision.* `lowering_guard`: on a node whose level is not Open, an **agent** change whose resulting effective sensitivity
is lower than the stored one is refused (`node_access_denied`, rule `L1`) — in `mutate_entry` (update, rotate, every
field op) and in `entry.undo` before anything moves. The owner may lower it; an agent may raise it. Since an agent can no
longer lower the stored value, approval is decided on the stored sensitivity, which is the maximum of what was stored and
what any agent edit inferred.

*Evidence.* `tests/security_levels.rs::p1_3_an_agent_cannot_lower_an_entrys_sensitivity_on_a_guarded_node`,
`::p1_3_an_agent_cannot_undo_the_owners_raise_of_sensitivity`.

### P1-4 · Only the owner accepts or discards a held entry

*Finding (confirmed).* `vault.pending_accept` / `vault.pending_discard` checked only `create`; on a Sealed node an agent
could accept its own held write, or discard another caller's.

*Decision.* Both refuse an agent-origin caller first (`capability_not_held`), before anything else is checked; a person's session keeps the `create` gate it had (the locked-node answer order is unchanged).

*Evidence.* `tests/security_levels.rs::p1_4_only_the_owner_accepts_or_discards_a_held_entry`.

### P1-5 · The Touch ID unlock never hands an owner session to an identified agent; the prompt names who asked

*Finding (confirmed).* `vault.unlock {method: "device"}` minted an owner `HumanUi` token for any socket caller behind a
generic "Unlock CredMgr" prompt; a prompt-injected agent running `credmgr unlock --touch-id` gets the owner's session from
one tired tap, and dismissals were not counted in the backoff.

*The origin model.* Scope resolution (`scope.rs`, `06 §4`) gives every caller one of: a token's origin (an owner login
is `HumanUi`, an agent token `Agent`); no token with a cwd inside a registered workdir → that project's agent scope
(`Agent`); no token otherwise → global list-only (`Agent`). So **every** token-less caller is `Agent` for access — the
human CLI before it unlocks included, because the broker cannot tell a person's terminal from an agent's shell: both
are the same binary, same uid, over the same socket (peer pid/cwd are advisory, AR-5). "Never hand a token to an
`Origin::Agent` caller" read literally would therefore break `credmgr unlock --touch-id` and the app's Lock screen. The
rule this ADR adopts for the device unlock:

1. **Identified agent → refused before any prompt** (`capability_not_held`): an agent token; or no token from inside a
   registered project folder (`scope::match_workdir` on the caller's cwd — the place CredMgr's own model says agents run).
2. **Anyone else** (the person's terminal elsewhere, the desktop app launched by Finder) **may unlock, but the Touch ID
   dialog names the requester**: `Unlock CredMgr for <name> (pid N) <- <parent> <- <grandparent>, in <cwd>`, built by
   `peer::describe` from the connecting process (`proc_pidinfo` on macOS, `/proc` on Linux). The server owns the `_peer`
   param: whatever a client sends there is discarded and, for `vault.unlock`, replaced.
3. **A dismissed or locked-out prompt counts as a failed attempt** in the per-uid backoff (`server.rs`), exactly like a
   wrong passphrase: five in a row and unlocking pauses.

The passphrase unlock is unchanged (knowing the passphrase is itself the proof of intent). *Residual risk, stated:* an
agent that leaves its project folder before asking is not identified by rule 1; rule 2 shows the person who is asking and
from where, and rule 3 bounds repetition. `SECURITY.md` says so.

*Evidence.* `tests/presence.rs::p1_5_an_identified_agent_never_receives_a_session_from_touch_id` (agent token and
project-folder caller refused, the stand-in helper never invoked, the vault stays locked);
`::p1_5_the_touch_id_prompt_names_who_asked_and_a_dismissal_counts_against_the_backoff` (the dialog text carries the
test process's pid and cwd, a client's `_peer` is discarded, the sixth attempt after five dismissals is `rate_limited`).
Both run on any Unix host through a shell-script stand-in for the helper.

### P2 fixes

* **P2-1 `search.content` is not an oracle.** An agent's content search skips every entry on a Sealed node and every
  entry a Guarded node would hold for approval. `tests/security_levels.rs::p2_1_content_search_is_not_an_oracle_for_what_an_agent_cannot_reveal`.
* **P2-2 `node.gate_verify` is persisted** (`PERSISTED_OPS`): a spent recovery code and the TOTP replay floor survive a
  restart. `tests/node_gate.rs::p2_2_a_spent_node_code_stays_spent_across_a_restart`.
* **P2-3 a rekey stage is removed crash-safely, and a stale one never overwrites newer data.** `remove_stage` unlinks
  `plan.sealed` first and durably, then the rest (a stage without a plan is inert). Roll-forward installs a staged file only
  when the live file does not already have the planned digest and — for an entry or the note — the manifest still names
  the planned digest (an edit after the commit is newer than the stage and is kept); the staged key is installed only when
  the live key is not already the new one. A failed cleanup after a committed rekey is reported, not swallowed.
  `tests/rekey.rs::p2_3_a_crash_while_the_stage_is_being_removed_still_unlocks`,
  `::p2_3_a_stage_left_behind_never_overwrites_a_later_edit` (two new test seams, `RekeyFault::CleanupCutShort` and
  `StageLeftBehind`).
* **P2-4 the enrolment is bound into the signed registry, and enrolling needs proof of possession.** *On-disk change:*
  `registry.json` gains `presenceKeys` (the enrolled public keys). With it present, `keys/presence.enroll` is ignored for
  the list (still written, for an older daemon and the rotation that re-signs it, and still verified when present — a
  tampered file is still an integrity error). *Migration:* a registry written before ADR-148 has no `presenceKeys`; its
  list is read from the file once and carried into the registry by the next write (`presence.enrol`/`unenrol` are now
  persisted ops). The one-time window — a file deleted before that first write — is stated, not closed. *Possession:*
  `presence.challenge {op: "presence.enrol", params, possession: true}` issues a challenge (op tag
  `presence.enrol#possession`, never a dispatchable op, so the proof cannot be replayed as a presence proof) even with
  nothing enrolled; `presence.enrol` verifies `params.possession` against the key being enrolled, after any existing key's
  presence proof (so a refused request never burns it). The CLI and the desktop shell sign it themselves.
  `tests/presence.rs::p2_4_deleting_or_replaying_the_enrolment_file_does_not_unenrol_and_enrolment_needs_possession`.
* **P2-5 the presence refusals run without the Secure Enclave.** Tests sign with a software P-256 key
  (`tests/f1_support::Signer`); every presence test in `presence.rs`, `f1_ops.rs`, `node_gate.rs` and `rekey.rs` now runs
  on Linux CI, plus `p2_5_at_most_eight_keys_and_the_oldest_of_sixty_four_challenges_is_evicted`. Only the real Touch ID
  unlock journey still needs the unattended test helper.

### P3 — fixed

Restore refuses `keys/root.wrap.se` and names that differ only in case, uses checked arithmetic for
lengths, and stages under an unpredictable name. `credmgr agent init` refuses a symlinked `CREDMGR.md`; both agent-config
writers (CLI and app) create backups and temp files new (`O_EXCL`), with the final mode from the start and an unpredictable
temp name, and never overwrite a backup made in the same second. The app's connect diff masks every value inside an `env`
object, and connecting refuses rather than write a bare `credmgr` command. A release build ignores
`CREDMGR_PRESENCE_HELPER` and refuses a helper whose probe is not the production variant; the trust placed in the helper for
the ephemeral ECDH is documented at `seal_to_public`. `sign-notarise.sh` rewrites the tarball's own `SHA256SUMS` after
re-signing and no longer swallows a checksum failure; the release verifier also checks the helper inside `CredMgr.app`.
`orphan.destroy` holds an explicit list to `count` before the presence proof is spent. `entry.import_env`'s dry run passes
the node's read gate. The MCP forbidden list names `node.rekey`, `orphan.destroy`, `node.export` and the four
`node.gate_*` ops (I-13 asserts it). The export's no-replace placement is atomic (a hard link), its hint names
`credmgr gate verify [--node <id>]`, and `age_format::Recipient` neither prints nor keeps its passphrase (redacted `Debug`,
zeroised on drop). A `.env` line that is only base64 padding after `=` is refused, not imported as a pair.

### P3 — deferred

* Dropping the rollback counter from archives: tried and reverted. Without it a restored vault refuses to open unless
  `credmgrd` is started with `CREDMGR_ACCEPT_MISSING_ROLLBACK_COUNTER=1` (the "missing-counter path" is an explicit
  operator override, not an automatic accept), so it needs a restore-scoped accept marker designed first. **Done
  2026-11-20: the amendment below (the restore ticket and its one-shot marker; the counter is no longer archived).**
* `destroy.rs` leftover journal vs a reused node id (rated PLAUSIBLE): **not reproducible, guarded by `crates/brokerd/tests/f1_ops.rs::a_leftover_destroy_journal_never_deletes_the_archives_of_a_node_that_took_a_freed_id` (2026-11-20).** A crash restarts the broker and every unlock applies the journal before a node can be created (`durable.rs::load_from_disk`); a broker that survives a failure still has `node.create` refuse the id while `archive/<id>` exists (ADR-079 F-d). One narrow gap was real and is closed: the journal removed `archive/<id>` *first*, so for the instant before the sibling `removed-entries/<id>` and `entry-history/<id>` were removed the id was free; it now removes `archive/<id>` *last*, keeping the guard up until everything is gone. No journal change (no node generation) was needed.
* Refusing `credmgr restore` while the broker runs: the probe would reach the default socket, which the restore tests do
  not isolate; needs the test environment first.
* The CLI restore "wrong messages" (`main.rs:1863-1871`): the finding does not say which message is wrong; the counter
  messages were updated with the counter change.
* Pruning old agent-config backups: a retention policy is a product decision.
* The desktop shell's own `CREDMGR_PRESENCE_HELPER` override: the shell's real-app suite runs it; gating it needs that
  suite's build path checked first.
* Zeroising every copy of an export passphrase (the request JSON holds one before the broker sees it).
* Moving the ephemeral ECDH out of the helper into Rust.

**Not changed.** No new broker op, no new MCP tool, `crates/core` stays I/O-free (the only core changes are a `Debug`/
`Drop` on `Recipient` and a `.env` parse rule), `#![forbid(unsafe_code)]` holds (the new `proc_pidinfo` call lives in
`peer.rs` beside the existing ones, under that module's scoped allow).

### ADR-148 addendum · the independent verifier's follow-ups (2026-11-07)

An independent verifier passed ADR-148 (ship) and listed eleven follow-ups. Each was confirmed in the code first.

1. **P2 — the help overclaimed.** `docs/help/features.json` (→ `HELP.md`, the in-app help, the agent manifest) said "An
   AI agent never receives an unlock this way", which contradicts the residual above: `peer::describe` walked at most
   four processes, and an agent can push itself off that chain (nested `sh -c`, a double fork to pid 1), name its
   binary `zsh` and `cd ~`. *Fixed:* the help now states the real guarantee (refused to an agent the broker can
   recognise; anyone else reaches it as the person's terminal does; the names are a hint, not proof), and `SECURITY.md`
   says the dialog's "who asked" is a hint read from a process table the requester controls. `describe` now walks the
   whole chain to pid 1 (at most 32 steps), shows four names, then `… (N more)`, then `launchd`/`init` — or
   `? (chain cut short)` when a lookup fails first; a requester whose parent is pid 1 shows `<- launchd` right after
   it. *Test:* `peer.rs::the_requester_chain_is_walked_to_the_root_or_marked_cut_short`.
2. **P2-5 gap — the Touch ID journey still needed the helper.** *Fixed:* `tests/presence.rs` gains a shell-script
   stand-in for the helper that answers `enroll`/`ephemeral` with fixed values and `ecdh` (the prompt) per test —
   touch, dismiss, or never answer; ECIES seal and open agree whenever both sides use one shared secret, so the real
   root key round-trips. *Test:* `p2_5_touch_id_unlock_survives_two_rotations_and_a_removed_wrap_stays_removed`
   (the tag re-signed by rotation 1 verifies at rotation 2, the old root's tag is `Invalid`, a fresh daemon unlocks by
   touch after each). The P1-1/P1-5 tests now set Touch ID up through `device.enrol` on the same stand-in.
3. **P2-3 nit — a committed rekey whose cleanup failed answered an error.** *Fixed:* it answers success with
   `cleanupWarning` (and a `credmgrd: warning:` line); the next unlock settles the stage as before.
   *Test:* `tests/rekey.rs::p2_3_a_stage_left_behind_never_overwrites_a_later_edit` (the `StageLeftBehind` seam is now a
   failing removal; the op succeeds with the warning, and after a later edit and a restart the stage is gone and the
   edit kept).
4. **P3 — `rebuild::apply` reverted `presenceKeys` to the candidate's.** *Fixed:* `apply` keeps the registry on disk's
   `presenceKeys` (and `deviceWraps`, item 10); `rebuild::diff` shows `presence_keys_kept` and
   `presence_keys_not_restored` (in `maintenance.doctor`'s diff as `presenceKeysKept` / `presenceKeysNotRestored`).
   *Test:* `rebuild.rs::a_rebuild_keeps_the_registry_on_disks_presence_keys`.
5. **P3 — the `CREDMGR.md` symlink pre-check was racy.** *Fixed:* `credmgr agent init` reads it with
   `O_NOFOLLOW | O_NONBLOCK` (constants from `libc`, now a unix dependency of the CLI; no unsafe code) and checks the
   **opened handle** is a regular file; the backup and the replacement take that handle's mode. The backup's bytes are
   the ones that read returned. *Test:* `agent.rs::a_symlinked_credmgr_md_is_refused_and_two_backups_in_one_second_do_not_collide`
   (a link and a directory are refused by the read itself).
6. **P3 — a Touch ID prompt left to the 180 s timeout read as `unavailable` and cost nothing.** *Fixed:* the helper call
   fails with code `timed_out`, which the broker maps to `cancelled`, so it counts in the backoff like a dismissal
   (message: "dismissed or timed out"). `Helper::with_timeout` is a test seam. *Test:*
   `tests/presence.rs::a_touch_id_prompt_left_to_time_out_counts_like_a_dismissal`.
7. **P3 — a bare `capability_not_held` from `credmgr unlock --touch-id` in a project folder.** *Fixed:* the CLI explains
   (agent token or registered project folder; run it outside a project folder or use the passphrase), and the
   "set it up first" hint now appears only for `not_enrolled`. *Test:* `main.rs::a_refused_touch_id_unlock_says_why_and_what_to_do`.
8. **P3 — `presence.unenrol` changed the file and memory before the registry.** *Fixed:* it writes the signed registry
   first (the edit applied to the document being signed), then memory, then `keys/presence.enroll`; it is no longer in
   `PERSISTED_OPS` (it persists itself). *Test:* `tests/presence.rs::a_failed_unenrol_changes_nothing_and_a_successful_one_survives_a_restart`
   (a failing registry write leaves memory, the file and a restart with both keys; a successful one survives a
   restart and a replayed two-key file).
9. **P3 — the `.env` padding rule refused `SEP==` and the whole file.** *Fixed:* only a line that is nothing but base64
   then one or two `=`, a multiple of four long (no key separator of its own; with a single `=` it must also look like
   base64 — a digit, `+`/`/` or both letter cases — so `PLACEHOLDER=` stays an empty value), is refused — that line alone, reported by
   number (`Parsed::refused_lines`; the CLI warns and its JSON carries `refusedLines`; the app's preview carries it
   too). `SEP==` imports as `SEP` = `=`. *Tests:* `dotenv.rs::a_padded_base64_tail_on_its_own_line_is_not_a_pair`,
   `::a_value_that_is_only_padding_is_still_a_pair_when_the_line_is_not_base64`, `env_preview.rs::a_lone_padded_base64_line_is_skipped_by_number_and_the_rest_previews`.
10. **P3 — a validly tagged `root.wrap.se` put back after `device.remove` re-enabled Touch ID unlock.** *Decision and
    on-disk change:* `registry.json` gains `deviceWraps` (the public points, hex, of the wraps this vault set up).
    `device.enrol` writes the wrap and then a registry naming it (a failure leaves the file inert); `device.remove`
    writes a registry naming none **before** deleting the file. A wrap the registry does not name is not set up:
    `vault.unlock {method: "device"}` refuses it before any prompt (a daemon that has not loaded yet reads the
    registry unverified only for that early refusal, and checks the verified list again after the Enclave opens the
    root key, locking if it does not name the wrap); a rotation leaves it untouched and seals nothing to it;
    `touchIdUnlock` reports false. *Migration:* a registry without `deviceWraps` names the wrap on disk at the first
    load (unless its tag fails under the root key), carried by the next write — the same stated one-time window as
    `presenceKeys`. `rebuild::apply` keeps the on-disk list. *Tests:* item 2's journey test (the put-back wrap gets no
    prompt from this daemon or a fresh one, and a rotation leaves it byte-identical), and
    `p1_1_a_planted_touch_id_wrap_never_receives_the_new_root_key` (an attacker's validly tagged wrap at an unnamed
    point is never re-sealed).
11. **Stated — the export's plaintext.** `node.export` now wipes every string value of its intermediate JSON document
    once it is serialised. Not covered, and stated: `serde_json::to_vec`'s growth reallocations, the loaded entry
    documents and the request's own copy of the passphrase may leave plaintext in freed memory.

**Not changed.** No new broker op, no new MCP tool, `crates/core` stays I/O-free (its only change is the `.env` rule and
the additive `refused_lines`), no new unsafe code.

### ADR-148 amendment · the restore-scoped accept marker, and the counter left out of archives (2026-11-20; K-23 (e))

*Deferred item.* "Dropping the rollback counter from archives: tried and reverted … needs a restore-scoped accept marker
designed first." The archive carried `_state/vaultGeneration.counter` so that a vault restored onto a new Mac (no counter
there) could open; that made every archive a matched old pair (K-8). Dropping it alone left a restored vault refusing to
open without the operator-wide `CREDMGR_ACCEPT_MISSING_ROLLBACK_COUNTER=1`.

*Decision.* (`crates/store/src/restore_marker.rs`.)
1. **The archive carries a restore ticket, never the counter.** `maintenance.backup` (which holds the root key) runs
   `backup::create_backup_with_ticket`: the vault's files as before, and `_state/restore.ticket`
   `{v, registrySha256, generation, issuedAt, hmac}`, the hmac under the root key (label `restore-ticket/v1`) over the
   SHA-256 of the exact `registry.json` the archive carries, that registry's `vaultGeneration` and the time. The ticket is not
   a counter (another file name, another label, another shape) and cannot be planted as one. A vault whose `registry.json`
   has no readable generation is not backed up (`malformed_request`).
2. **`credmgr restore` writes a one-shot marker, only where there is no counter.** The ticket is checked for structure before
   anything is written (a damaged ticket restores nothing). With no counter in the state directory, the restore writes
   `restore-accept.marker` there (the ticket, the folder it restored into, the time) and reports `counter: "acceptMarker"`
   (`CounterOutcome::AcceptMarker`). A counter already there is kept and decides, as before (`keptExisting`), and no marker is
   written. An archive that carries a counter (made before this change) is restored as before (`restored`).
3. **The first unlock checks and consumes it.** With no counter and no environment override, the broker refuses unless a
   marker is there whose ticket verifies under **this vault's** root key and names **exactly** the `registry.json` bytes on
   disk and the generation of the (verified) registry. Then it writes the counter at that generation and deletes the marker
   (the counter first: a crash between the two leaves a counter, which then decides). Anything else is refused with the marker's
   reason (another vault's marker: another key; an edited generation or tag: the tag does not verify; a marker for an older
   registry: another registry), and the vault stays closed. The folder named in the marker is a record, not a check: the
   restore has no root key to sign it, and a restored vault may be moved into place before its first unlock.
4. **What it accepts, and what it does not.** A marker can only ever open the registry its ticket was signed for, under the
   key that signed it: planted again after the vault moved on, it names an older registry and is refused; planted again with
   the registry unchanged, it opens the same registry, which is no rollback. Forging one needs the root key. A same-user
   attacker holding an old archive and its backup passphrase can still restore it into a state directory with no counter, as
   they could restore its counter before: the K-8 bound (passphrase, same-user write, a matched old pair) is unchanged, the
   pair is now archive plus ticket. Deleting the live counter alone is refused as before (review H1(a)).
5. The environment override stays for a vault folder moved without its state directory.

*Tests.* `store/src/restore_marker.rs` (2: accepted for its key, registry and generation only; a re-pointed ticket does not
verify); `store/src/backup.rs::a_ticketed_archive_leaves_the_counter_behind_and_restores_a_marker_only_where_none_is`;
`brokerd/tests/backup_restore.rs`: the full backup and restore opens through the marker, which is consumed and leaves the
source's counter bytes; `a_missing_counter_without_the_restore_marker_is_still_refused` (and the live vault's deleted counter);
`a_restore_marker_for_another_vault_or_a_forged_one_is_refused` (another vault's marker, an edited generation, a replaced tag,
then its own marker accepted once); `a_consumed_marker_planted_again_after_the_vault_moved_on_is_refused`;
`src-tauri/tests/backup_restore.rs` (the app's restore through the real `credmgr` answers `acceptMarker` and the restored vault
unlocks after being moved into place).

## ADR-149 · A Touch ID prompt must not make the page drop its own answer (2026-11-08; amends ADR-098)

**Defect (proven in the built app, 2026-11-08).** "Show seed" with Touch ID set up: the macOS sheet appears, the user touches, the
broker allows `totp.seed` (the audit shows `allow`), and the app shows nothing. The sheet takes window focus, so the shell emits
`credmgr://window-inactive` with reason `blurred`; the page wiped its reveals, which cancelled the reveal ticket, and
`holdFetched` dropped the answer on arrival. `orphan.reveal` (the orphaned node's "open") is gated the same way.

**Decision.**

1. The model counts the presence-gated requests THIS page started and has not seen settle (`presenceInFlight`), incremented and
   decremented in a `try/finally` by `VaultModel.withPresence`. It wraps `totp.seed` (`readTotpSeed`) and the orphaned node's
   reveal (`VaultModel.reveal` on the orphan node). No other call holds a value behind a Touch ID sheet.
2. `VaultModel.windowInactive(reason)` is the single decision point the page's window-inactive handler calls. For reason `blurred`
   while a request is in flight, and for 1.5 s after the last one settles (the focus-return ordering of the system sheet), it
   wipes nothing. `minimized`, `hidden` and any reason this build does not know wipe at once, in flight or not. Lock is a
   separate path (`clear()`) and always wipes.
3. **Kept simple on purpose:** inside that window nothing is wiped on `blurred`, including a value revealed BEFORE the prompt.
   The user is at the sensor, and telling "the sheet took focus" from "the user switched apps" is not possible from the event.
   The exposure is bounded: at most the request's duration plus 1.5 s, a value still re-masks on its own timer, and a real
   hide or minimise still wipes.
4. The browser-level `visibilitychange` path is unchanged: a really hidden document wipes (and auto-locks when so set).

**Not changed.** No new broker op or MCP tool; the broker's presence check is untouched; no secret is kept longer than its
reveal window. Tests: `tests/unit/model.test.ts` (window-inactive rule), `tests/e2e/wp-b-entries.spec.ts` (blurred during
`totp_seed` keeps the seed; `hidden` during it still drops it).

## ADR-150 · Confirm before showing secrets: a vault setting, off by default, that makes the owner's own login re-prove a person is at the keyboard before a value leaves the broker (2026-11-08)

Numbering note: ADR-149 (the Touch ID "presence-in-flight" blur grace) is written on another branch.

**Context.** The operator asked (2026-11-08) for Touch ID to work once and, after that, for a fingerprint or the
passphrase to be needed whenever the user wants to *see* credentials — a setting, default off; once confirmed, no
further prompt for a chosen time; and, in Pro, a choice between asking every time and asking only for very
high-importance credentials. Before this ADR an unlocked owner login showed any value on request: the unlock (and the
idle lock, ADR-043/065) was the only human check.

**Threat it addresses.** A person at a Mac whose vault is already unlocked: a colleague at a desk left for a minute, a
borrowed or shared laptop, someone looking over the shoulder who then takes the keyboard. Without it they can reveal,
copy or read one-time codes for every entry until the idle lock. With it each value needs the owner's finger or
passphrase (per trust window, or per value).

**What it does not address.** Malware running as the user (it can read the screen, wait for the owner to confirm, or
read memory); an attacker who already knows the passphrase; changes that are not reads — editing, removing, creating
grants or agent tokens, registering a project folder and reading as an agent (agent reads answer to the node's security
level, ADR-140, and lowering that needs Touch ID already; every such change is audited); `search.content` (ADR-132), which
answers only ids and names and is rate-limited; `notes.read`, which holds context, not credentials; the copy left on a
screen or clipboard after a value was shown (the reveal window and the concealed clipboard handle that). "Only high and
critical" trusts the entries' sensitivity labels; lowering one out of that band is therefore gated too (below), but a
person who can confirm can relabel.

**Decision.**
1. **The setting.** Vault policy, in the signed registry, on the `global` node's policy as `revealConfirm:
   { mode, windowSeconds, scope }` (`credmgr_core::reveal_confirm`, pure). `mode`: `off` (default) · `window` (one
   confirmation, then no prompt for `windowSeconds` ∈ {60, 300, 900, 3600}, default 300) · `everyTime` (a
   confirmation is good for ONE gated request within 60 s). `scope`: `all` (default) · `high` (only entries whose
   sensitivity — the plaintext manifest projection ADR-140 already uses — is high or critical). Settings › Security
   shows the on/off switch and the trust window; the Pro-only rows show "When to ask" and "Which secrets".
2. **Set with the existing `node.policy`** on `global` (refused on any other node: `malformed_request`), by the
   owner's own login only (an admin token that is not a login, and every agent, are refused). Turning it on or making
   it ask more needs nothing. **Turning it off or making it ask less** — for any sensitivity, the requirement goes down
   (`RevealConfirm::weakened_by`) — needs a confirmation made in the last 60 s, which the change uses up; otherwise
   `confirmation_required` with `operation: "node.policy"`.
3. **Confirming: `session.confirm`** (new op, the 76th). The owner's login only. `{passphrase}`: it must open
   `root.wrap.pass` to the root key this unlocked vault runs on (compared in constant time, nothing kept); a wrong one is
   `wrong_passphrase` and **counts in the per-uid unlock backoff** (`server.rs`; a backed-off uid gets `rate_limited` for
   either form). No passphrase: a presence proof for `session.confirm` with params `{}` (ADR-098's challenge, Touch ID
   dialog sentence "Show your saved secrets"); without one, the long-standing `presence_required`, which the desktop
   shell and the CLI already turn into the Touch ID prompt when this Mac has a presence key. Answer
   `{confirmed, method, expiresIn}`. A confirmation belongs to one login session (its public id), lives in memory only,
   and **every lock ends it** (`lock()` clears them with the sessions). Hiding or minimising the window does not end it:
   the app already wipes every revealed value when the window hides, and the trust window is short and the user's
   choice; the idle and screen locks still end it.
4. **Enforcement, in the broker only.** `entry.reveal` (and so the shell's `entry_copy`, which reveals Rust-side) and
   `totp.code` check, last — after every access, approval and second-factor check, so a request refused for another
   reason never spends a confirmation — that a non-agent caller holds a confirmation meeting what the policy asks for the
   entry's sensitivity; else **`confirmation_required`** (new error code, the 27th: `operation`, `mode`, `windowSeconds`,
   `remedy`). A caller that is not a live login can never confirm and is refused whenever the policy asks anything.
   Under `scope: high`, an owner edit (`entry.update`, `entry.rotate`, a `field.*` edit, `entry.undo`) that takes an
   entry from high/critical to below needs a fresh confirmation too (`lowering_guard`), or "only high" could be escaped
   by relabelling first.
5. **The value-returning ops, decided one by one** (`corpus_check.broker_ops()`): `entry.reveal`, `totp.code` — gated.
   `totp.seed`, `orphan.reveal`, `node.export` — not gated: each already needs a presence proof for the exact request
   (export also a fresh second factor), which is stronger than a window, and adding a confirmation would put a second
   prompt in front of the same request. `util.generate` returns a new value, not a stored one. `vault.approval_decide`
   (approve, session form) releases a staged value to whoever asked — an agent, or the owner's own login after a node
   lock — so it is gated too, and so is the retry that collects it (amendment below; this row said, wrongly, that an
   approval only ever releases to an agent). Every other op returns no value.
6. **Agents are unaffected.** Their reveals already answer to the node's security level and the owner's one-tap
   approvals (ADR-140, ADR-042), an agent can never hold a login, and an MCP agent has no tool for `session.confirm`
   or the policy (no new MCP tool; I-13 unchanged).
7. **Clients.** The app catches `confirmation_required` in one place (`src/lib/bridge.ts`), shows "Confirm it's you"
   (Touch ID when this Mac has a presence key, else the passphrase; either may be chosen), calls `session.confirm`, and
   retries the original request once; a cancel shows nothing. `credmgr get` (and any other command that meets the refusal) does the same at a terminal
   (Touch ID first, else a passphrase prompt on stderr, never argv); from a pipe they say to run `credmgr confirm`
   (passphrase from stdin, or `--touch-id`) first.

**Migration.** A registry written before ADR-150 has no `revealConfirm`: it reads as off, and the field is written only
when it differs from the default, so an older registry re-signs byte-for-byte as before. Nothing else is stored.

**Tests.** `crates/core/src/reveal_confirm.rs` (needs, weakening, satisfaction), `crates/brokerd/tests/reveal_confirm.rs`
(off by default; refused until confirmed; window expiry; `totp.code`; every time; high only and the band edge; weakening
and strengthening; vault-only and well-formed; survives a restart; lock ends it; one login only; agents unaffected;
Touch ID proof; wrong passphrase and the shared backoff; wire shape), `crates/cli/tests/reveal_confirm_cli.rs`, and the
desktop unit, Playwright and real-daemon specs named `reveal-confirm`.

**Amendment (2026-11-08, adversarial review fixes).** Each fix has a refusal test in
`crates/brokerd/tests/reveal_confirm.rs` that fails without it.
- **P0 — the approval path.** `vault.node_lock` → `entry.reveal` (approval pending) → `vault.approval_decide
  approved:true` → `entry.reveal` handed the owner's login the value with no confirmation: the gate ran only on the
  unlocked branch. Now (a) `reveal_via_approval` applies the gate to a non-agent caller before it consumes the
  approval and returns the staged value, and (b) `vault.approval_decide` (approve, session form) needs the deciding
  login to hold a confirmation meeting the policy's need for the entry's sensitivity, checked after the value is
  staged and before the decision is stored. Chosen over "refuse an owner approving its own login's request" because
  approving releases a stored value whoever asked, and an unattended login could otherwise release a Guarded or Sealed
  node's value to an agent route it controls. Deny is never gated; the locked-vault form (`passphrase` + `code`) is
  authorised by the unlock factors. In "every time" mode the owner's own lock → approve → collect costs two
  confirmations (one for the approval, one for the value). A decider that is not a live login never holds a
  confirmation and is refused whenever the policy asks. Tests: `locking_a_node_and_approving_is_not_a_way_round_it`,
  `every_time_asks_for_the_approval_and_again_for_the_value`, `denying_an_approval_is_never_gated`.
- **P1 — backoff reset.** A successful `session.confirm` reset the per-uid auth backoff, so a login could guess node
  or vault gate codes without limit by confirming between guesses. `session.confirm` now records failures only; only
  the other auth ops' successes reset the counter. Test: `a_successful_confirm_does_not_reset_the_backoff`.
- **P2 — wording.** The Settings caption and the help say the setting guards this app and the logged-in CLI, not
  agents (a token-less `credmgr` run from a registered project folder is an agent), and point to security levels.
- **P3-a.** An entry with no manifest row is gated as critical (it used to pass the gate). Test:
  `an_entry_missing_from_the_manifest_is_gated_as_critical`.
- **P3-b.** A `session.confirm` presence proof that does not verify (`invalid`, or a `cancelled`/`locked_out`
  reported in its name) counts against the backoff, as a dismissed Touch ID unlock does. The Touch ID prompt for a
  confirmation is shown by the client, so the broker sees a failed check only as an invalid proof. Test:
  `a_touch_id_confirmation_that_does_not_verify_feeds_the_backoff`.
- **P3-c.** `node.policy` spends the weakening confirmation only after the presence step and the registry
  invariants pass. Test: `a_weakening_refused_for_presence_keeps_the_confirmation`.
- **P3-d.** `entry.reveal` builds its answer (validating `fieldIds`) and `totp.code` chooses and checks its field
  before the gate, so a bad request never spends an "every time" confirmation. §4's "last" now means after the answer
  is built. Test: `a_bad_field_id_does_not_spend_an_every_time_confirmation`.
- **P3-e.** A confirmation made in "window" mode also counts as fresh for a weakening change within 60 s of being
  made (a fresh need asks only that it is under 60 s old and unspent), and that change spends it; the window itself
  keeps serving reveals, since a spent confirmation still meets a window need.
- **P3-f.** The CLI's confirmation passphrase is held in a `Zeroizing` buffer. It still echoes, exactly like
  `credmgr unlock`: the CLI forbids unsafe code and carries no no-echo prompt helper.
- **P3-g.** `RevealConfirm` no longer denies unknown fields when read, so a registry written by a newer version
  still loads (as `NodePolicy` does); known fields stay typed and range-checked. `node.policy` stays strict: a request
  naming a key outside `reveal_confirm::FIELDS` is `malformed_request`. Test:
  `a_request_with_an_unknown_policy_key_is_refused` and the core unit test
  `wire_shape_is_camel_case_and_forward_compatible`.


## ADR-151 · The design drop of 2026-11-08 merged: the Security page is grouped, "hide seed" hides only the seed, and nothing that changes behaviour is taken (2026-11-08)

**Context.** We sent the design side `DESIGN_RELAY_2026-11-08.md` (36 items the shipped window already had). Their drop of 2026-11-08 (`design-upstream/2026-11-08/`, reply in `BACKEND_STATUS_REPLY_2026-11-08.md`, not committed) brings their mock up to date with those 36 items, makes seven changes beyond them (their §2), answers Q1–Q8 and asks six questions. Merged three-way like ADR-092: base `2026-10-26/extracted/`, theirs `2026-11-08/extracted/`, ours `src/design/`. Rule: the window's behaviour, broker wiring, error routing, security rules, the VoiceOver fixes (`1a83f83`, `c748a1d`) and backend-owned copy win; only presentation is taken. Answers: `BACKEND_ANSWERS_2026-11-08.md`.

**Decision.**

1. **Taken (presentation only).** Settings › Security is grouped under three labels (their Q1): "unlock and confirmation" (Touch ID, Confirm before showing secrets and its child rows, Auto-lock, Reveal window), "on this screen" (Concealed clipboard, Screen capture), "who can read" (Two-factor gate). No row, control, binding or handler changed. The Operations panel's "Rotate root key" line says "Asks for Touch ID." instead of "Needs presence." (the same words the Advanced row already used).
2. **Their Q4 is taken: "hide seed".** While a seed is showing, its button reads "hide seed" and takes away the seed only; a code shown beside it stays until its own timer; the reveal button's "hide" still takes both. Hiding asks the broker nothing. A small change in `logic/inspector.js` (`showTotpSeed` toggles; `seedLabel`, `seedTitle`), one e2e test (`wp-b-entries.spec.ts`, "Q4").
3. **Already in the window, nothing to take:** the 36 relay items, Agents second in the Settings nav with no "Agents · LLM", the licence-tab copy (Admin@freexstudio.com paragraph, trademarks and font paragraphs), the column-flex narrow inspector, the Help dialog width, the games hint, the input border `--mute` (ADR-147).
4. **Not taken.** Their 17 sample Help topics (`help-data.js` stays generated from `docs/`, 163 topics); the "Restore from backup" Operations row and its passphrase prompt (restore is the offline `credmgr restore`, ADR-112; there is no broker op and the window must not offer one); their mock data, mock flows and placeholder commands (`maintenance.restore`, `credmgr mcp` without the path); their lock-screen, confirm, import, alias, agents and Touch ID mock logic (the window's real versions stay); the vault-wide Security-level row and level cards they removed (we never had them).
5. **Open, not decided here.** Their Q2, renaming the agent level "Sealed" to "Strict": the operator's decision (the word collides with sealed nodes). Their Q6, a disabled Touch ID row on a Mac without a Secure Enclave: not built (the row stays hidden). *[Status as of 2026-11-20: built in ADR-156; `apps/desktop/src/design/logic/settings.js` shows the row disabled with "This Mac has no Secure Enclave" and a plain-words protection line.]*

**Tests.** `npm run check`, `npx vitest run`, `npm run test:e2e` (new Q4 test), `test:csp`, `test:design`, `test:real`; `tools/release_verification_check.py` (the "show seed" row now describes the toggle; §16 lists what to look at in a built app).


## ADR-152 · The strictest security level is called "Strict" for users; `sealed` stays the stored value (2026-11-08)

**Context.** ADR-140's three levels are Open, Guarded and Sealed. "Sealed" also names an unrelated act: sealing a node into Orphaned (`node.seal`, ADR-079, ADR-098), with its "Seal node" dialog, "sealed entries", "sealed nodes" restorable for 7 days and the `.is-sealed` rows. A person reading "the node is Sealed" could not tell whether an agent was held or the node had been removed. The design side raised it (Q2 of `DESIGN_RELAY_2026-11-08.md`, left open in ADR-151); the operator decided on 2026-11-08.

**Decision.**

1. **The level is named "Strict" wherever a person reads it:** the node inspector's "agents here" control, its captions, titles and the toast ("Security level is now strict."); Help (`docs/help/features.json`, regenerated `HELP.md`, `help-data.js`, `credmgr-capabilities.json`); the agent prompt and `CREDMGR.md` (`Security level: **Strict (stored as sealed)**`); the broker's rule `L1` refusal text and the MCP tool descriptions; `credmgr whoami` and the `node policy` report (`strict`); the docs that name the level.
2. **Nothing stored or sent changes.** `NodePolicy.securityLevel` is still `open` | `guarded` | `sealed` in the registry, `node.policy`, `graph.snapshot`, `whoami` (`level`), the bridge, MCP and the CLI's JSON. No registry format change, no migration, no new operation, error code or MCP tool. `SecurityLevel::parse` (the wire parse) still accepts only `sealed`; a new `SecurityLevel::parse_input` accepts what a person types (`strict` or `sealed`), and `SecurityLevel::label` gives `strict` for display.
3. **CLI.** `--security-level` takes `open|guarded|strict|sealed`; `strict` is an alias for `sealed` and is sent as `sealed`. The usage text lists `strict`.
4. **Node sealing keeps its word.** "Seal", "Seal node", Orphaned, "sealed entries", "sealed nodes", `node.seal` and `orphan.*` are untouched, as is the colourless sealed style.
5. **Precision where it matters.** Agent-facing and security text says "Strict (stored as `sealed`)" once, so an agent or auditor can map the word to the stored value.

**Alternatives rejected.** Renaming the stored value to `strict`: a registry format and wire change, a migration for every vault, and every older client would misread it, to fix a display problem. Renaming node sealing instead: "Seal" is the established, tested and documented act, with 7-day restore. A second display alias in the window only: the CLI, Help and the prompt would still say "sealed".

**Tests.** `registry.rs` unit test (`strict` parses for input, never on the wire, `label`, serde stays `"sealed"`); `credmgr-cli` unit test (the alias maps to `sealed`, others unchanged, a bad word refused); `credmgr-core` agentcfg test (the prompt says "Strict (stored as sealed)"); `apps/desktop/tests/e2e/agents.spec.ts` (the control reads Open / Guarded / Strict, no "sealed" in it, the toast says strict, the wire call is `sealed`; the node seal dialog still says "Seal node"). `tools/gen_help.py --check` and `corpus_check.py` clean.


## ADR-153 · The 2.x direction: use-don't-reveal first, then the doctor, licensing, sync, remote agents; doc 23 is merged as history (2026-11-08)

**Context.** The operator (live chat, 2026-11-08) asked for one plan covering quick wins, gaps against similar apps, LLM connectivity from local and cloud agents with credentials kept offline, encrypted backup and sync across machines and phones, a consolidating doctor, and store sales with one-time tiered licences. Four research memos (`docs/research/2026-11-08/`) checked each against `main` @ `9401093`. The unmerged `docs/23` (2026-10-30, branch `claude/credmgr-v2-post-release-7630e4`) had designed sync and model-blind agent use under a draft "ADR-094", a number `main` later used for a different decision.

**Decision.**

1. **The plan is `docs/26_PRODUCT_PLAN_2X.md`** (private: held back from the public export with `docs/research/`). Order: 0 finish 2.0.0 (signing; quick-win batch not started) → 1 use-don't-reveal (agent tokens, a `use` capability, `cmref:` references, `credmgr run`) → 2 the doctor → 3 licence and store → 4 backup and sync → 5 executor and remote agents → 6 Windows, Linux, phones, team. Each phase gets its own ADR and exit gate before it is built.
2. **`docs/23` is merged as a historical design record.** Its draft ADR is not adopted under any number; its live parts (no last-writer-wins, the conflict table, the executor rules, the four classes of agent access, F01) are carried by `docs/26` and later per-phase ADRs. Where `docs/23` and `docs/26` disagree, `docs/26` wins (sync transports start with a user folder, not a relay; agent use no longer waits for sync; device identity is P-256).
3. **F01 is recorded as a known risk now** (`PHASE8_AUDIT_REPORT.md` K-25, `SECURITY.md`): an agent whose node lets it reveal receives the value into its model's context, and CredMgr cannot take it back. It was found on 2026-10-30 and never recorded on `main`.
4. **Invariants every phase keeps:** `credmgrd` stays the single enforcement point with no network code (A-1, A-2, `deny.toml`); any networked part (sync helper, connector, breach-check helper) is a separate binary in its own Cargo workspace holding no node or root key; no value tool is ever exposed remotely; a licence never locks the vault.

**Stale references noted, not edited** (ADRs are history): `ADR-095` cites "`ADR-094` (`PRU-1`)", meaning the doc 23 draft, not today's ADR-094; `04_CRYPTO_AND_KEYS.md §1.1` and `05_THREAT_MODEL.md §9.3` say core has no asymmetric signature primitive (P-256 ECDSA has been there since ADR-098).

**Not decided here.** The eight operator questions in `docs/26 §9`.

## ADR-154 · The licence core: one-time, offline, P-256-signed certificates with a tier table; built, not wired (2026-11-08)

**Context.** The operator asked for store-ready one-time licences in tiers (one device, all devices, team) and "implementing the core if we can now". `ADR-095` designed a machine-bound, leased (35/400-day), Ed25519 licence checked in the shell. A one-time purchase and the store rules (research memo 04) need something else.

**Decision.**

1. **Format.** `CMLIC1.<base64url JSON payload>.<base64url r‖s>`, at most 8 KiB, signed with ECDSA P-256 over `"credmgr/v2/licence/v1\0" ‖ payload` by an offline publisher key named by `keyId` (rotation without breaking old licences). P-256, not Ed25519: `p256` is already a vetted dependency of core (ADR-098) and adds nothing to the tree. Supersedes `ADR-095` item 2's algorithm, binding and lease.
2. **One-time, not leased.** No expiry by default; `updatesUntil` says which builds are covered — forever. A build released later reports `upgradeRequired` and the old build keeps working. `expiresAt` exists only for invoiced or trial licences.
3. **Binding.** Solo: exactly one device fingerprint, `hex(SHA-256("credmgr/v2/device-fingerprint/v1\0" ‖ platform id))`. Plus: the vault's licence identity (`holderKey`) and/or up to 10 devices. Team: seats, no devices. A copied token fails on another device or in another vault.
4. **Tiers and entitlements** (`credmgr_core::licence::entitlements`, cumulative): Free = the whole vault and every security control, never reduced; Solo adds `doctorApply`, `breachCheck`, `scheduledBackup`, `extras`; Plus adds `sync`, `remoteAgents`, `mobileCompanion`; Team adds `teamVault`, `teamAdmin`. There is no entitlement for unlock, read, write, export, backup or any security control.
5. **Every failure is Free** (unlicensed, bad signature, unknown key, wrong device, wrong holder, expired, upgrade required, malformed, issued in the future beyond a day) — `ADR-095` item 4 stands.
6. **App Store builds** map StoreKit product ids (`com.credmgr.desktop.licence.{solo,plus,team}`) to the same table with `tier_for_store_product`; they never show a licence-key field (App Review 2.4.5(vi), 3.1.1).
7. **Where it runs** is decided when it is wired (Phase 3): the verifier is pure core code, so the shell and the broker can both use it; `ADR-095` item 6 is reopened, not yet superseded.

**Not decided here.** Tier names and prices, the publisher key ceremony, the issuer tool, the payment provider, editions (`docs/26 §9`). **Not changed.** Nothing is gated; no network call is added; `DONATE.md`, `PRIVACY.md` and the licence text are unchanged until a paid tier ships.

**Tests.** `crates/core/src/licence.rs` unit tests (12): cumulative tiers; a valid Solo licence; every failure maps to Free; tampered payload; domain separation; the update window; expiry and future issue; inconsistent payloads refused at issue; holder binding; store product ids; fingerprint; camelCase wire names.


## ADR-155 · The switchboard: one settings registry the app, the CLI and every LLM read and change; weakening changes from an agent wait for the owner (2026-11-09)

**Context.** The operator (live chat, 2026-11-09): any LLM, local or cloud, through MCP, the CLI or the broker, should discover, read and change every CredMgr feature and setting without the app window, so the user can just ask the model; the app must read the same registry so the two can never drift; a knowledge-base file for models, generated and drift-guarded; low-risk changes apply directly, anything that weakens security goes through the owner's step-up approval on their device; every change audited and revertible; nothing that weakens an existing control. Until now a model could change no setting at all: the app's preferences lived only in the window's local storage, and node policy was a human-only op (`node.policy`, `FORBIDDEN_OPS`).

**Decision.**

1. **One registry.** `credmgr_core::settings::SETTINGS` lists every setting: id, scope (vault or project), accepted values, default, what it is for, where it lives in the app, where it is stored, and which direction is weaker (`Risk`). 25 settings: the 15 app preferences (`app.*`, stored as `global.policy.appPrefs`, signed with the registry), the three "confirm before showing secrets" fields (`vault.confirmBeforeReveal.*`, `global.policy.revealConfirm`, ADR-150) and seven project policy fields (`node.*`, `<node>.policy`). `classify(old, new)` answers same, cosmetic, strengthens or weakens; a value the table does not know is read as the weakest.
2. **Eight ops** (`ops/switchboard.rs`, 76 → 84): `settings.list`, `settings.get`, `settings.set`, `settings.revert`, `settings.request_get`, `settings.request_list`, `settings.request_decide`, `settings.kb`. Six MCP tools (15 → 21): `credmgr_settings_list/get/set/revert/request` and `credmgr_kb`. `settings.request_list` and `settings.request_decide` are owner-only and on `FORBIDDEN_OPS`. CLI `credmgr settings list|get|set|toggle|revert|requests|request|approve|deny` and `credmgr kb`. Bridged in the app (84 commands).
3. **Safety tiers.**
   - The **owner** changes any setting under exactly the rules that already held: `admin` on the node; Touch ID to widen a project's reach (`descendantRead` on, siblings shared, a lower security level; ADR-098); a fresh confirmation to loosen `revealConfirm` (ADR-150). The app's own preference changes need nothing more than they did.
   - An **agent**'s cosmetic or strengthening change applies at once. A weakening change (a longer or no auto-lock, a longer reveal window, screen-capture protection off, a looser reveal policy, a lower security level, more agent access, two-factor relaxed, a longer or no project lock, wider reach) becomes a **request**: held in memory, ten minutes, at most 20 waiting, dropped at every lock, readable only by its requester and the owner.
   - The owner approves on their own device: `settings.request_decide` needs the owner's login **and** a fresh confirmation (`session.confirm`, Touch ID or passphrase, spent by the decision) — or a presence proof where the change widens reach. An agent can neither list nor decide requests. This is the existing step-up, not a new one.
   - An agent reaches project settings only for projects in its own scope; another project answers `not_found`, as it does everywhere else.
4. **Recorded and revertible.** Every applied change is appended to `global.policy.settingsHistory` (signed, at most 100) with the value it replaced, who made it (`owner`, or `agent:<node>:<hash>`), the reason and the request it came from; the broker's audit log records the op as for every op. `settings.revert` puts back a recorded value under the same tiers (an agent's revert that would weaken waits for the owner).
5. **The KB is generated.** `docs/LLM_KB.md` is `credmgr_core::settings::kb_markdown()` byte for byte (a core test fails on drift; `CREDMGR_WRITE_KB=1 cargo test -p credmgr-core the_committed_kb` regenerates it). It covers connecting (local MCP, `--print-config`, `agent connect`; cloud not yet, `docs/26` Phase 5), where data lives per OS, retention and backup, the switchboard and its tiers with examples, every setting, every feature and every MCP tool. `crates/mcp` holds its tool list to the registered tools.
6. **Not on the switchboard in this version** (owner-only operations, unchanged): unlock, Touch ID and second-factor enrolment, grants, creating, moving, sealing or deleting projects, rotating the root key, destroying orphans, backups, exports and restores. They are actions, not settings; each would need its own request type with its own preview (what is exported, what is deleted). The request queue is generic, so a later ADR can add them one by one without a new mechanism.

**Better split, noted.** The brief listed "export, sync pairing, delete" among the gated changes. Export and delete are actions (item 6) and stay owner-only rather than request-approvable for now: an approved export would hand a file to whoever asked, and a request carries no preview of the file yet. Sync pairing does not exist (`docs/26` Phase 4); when it does, enrolling a device is a control-plane change that needs the owner's presence, never an agent request.

**Alternatives rejected.** Letting an agent call `node.policy` with a step-up (one op, but its patch can mix weakening and strengthening fields and its refusal codes say nothing to a model); keeping app preferences in local storage and mirroring them (two sources of truth: the drift the operator asked to rule out); making the request approvable by a second agent token (an agent would approve its own weakening).

**Tests.** `crates/core/src/settings.rs` (6: unique ids and valid defaults, the app prefs are exactly the window's, validation, classification both ways, the KB names every setting/feature/tool, the committed KB is the generated one); `crates/brokerd/tests/switchboard.rs` (10: nothing changes while the vault is locked, list and rules per caller, owner changes survive a restart, refusals, owner step-ups, agent direct changes, agent request → owner confirm → applied, deny and lock, history and revert, the app path and the switchboard store the same field); `crates/mcp/tests/i13_tool_registry.rs` (21 tools reviewed; the KB lists exactly the registered tools; no tool decides a request); `crates/cli/tests/mcp_integration.rs::the_switchboard_end_to_end_from_a_real_mcp_client` (the real `credmgr mcp` and `credmgr` binaries against a running broker); the desktop drift guards (84 bridged commands, params, the TypeScript client).

**Amendment (wiring audit Q-1, 2026-11-21) · the switchboard keeps to an agent's capability ceiling.** The wiring audit (`research/2026-11-20/WIRING_AND_ISOLATION_AUDIT.md`, Q-1) measured that an agent's `settings.set` / `settings.revert` checked only that the node was reachable (`list`), never what the agent holds: an agent in a project set to `agentAccess: none` (`whoami`: `capabilities: []`) tightened that project's and Global's settings directly and filed a request to raise its own `node.agentAccess` to `read-write`. `scope.rs` says "`none` gets nothing, full stop", and the operator's standing requirement is that everything goes through the correct route and works only as planned. Item 3's agent tier is narrowed; the owner's tier and the request mechanism are unchanged.

1. **An agent reads the switchboard only while it holds `list`.** `settings.list`, `settings.get` and `settings.request_get` answer `capability_not_held` (`list`) to an agent holding no capability, before any node is looked at, so its own project, another one and one that does not exist answer alike. `settings.kb` stays readable by every caller: it is static text, the same for everyone, with no vault state in it (like `ops.json`).
2. **An agent changes only the settings of its own node, holding `update` there.** A setting is stored on one node: a project setting on its `node`, a vault setting (`app.*`, `vault.*`) on Global. An agent may change it — even make it stricter, even something cosmetic — only when (a) it holds `update` (`agentAccess: read-write`, or an agent token that carries `update` under that ceiling), (b) the node is **its own**, the node its scope sits on, so Global and the vault settings only for an agent whose scope is Global, and (c) `update` resolves there. Reaching another node through the access graph — Global for everyone (R3), an ancestor (R4), a shared sibling (R6), a grant (R7) — is entry access, never a say over that node's policy; those answer `capability_not_held` (`update`). A node the agent cannot reach still answers `not_found`, as everywhere else. The ceiling is checked before anything is read, so an agent with `none` learns nothing about which nodes or recorded changes exist. `settings.revert` applies the same gate to the node the recorded change touched.
3. **An agent never asks for more of its own access.** A weakening change to `node.agentAccess` on the agent's own node is refused (`capability_not_held`, `admin`), not queued: it is the agent widening its own scope (`10_API_AND_MCP.md` §3.2, "the definition of the boundary"). Through a real scope this cannot even be reached any more — holding `update` needs `read-write`, already the widest value — so the refusal is the backstop; narrowing itself stays the agent's to do. The owner changes it in the app or with their own login.
4. **Unchanged.** On its own node, an agent's cosmetic or strengthening change applies at once and a weakening one becomes a request only the owner decides, with a fresh confirmation (and Touch ID where it widens reach): ADR-155's rule. `settings.list` now says, per setting, what **this** agent may do (`read only` where item 2 refuses; `direct when stricter; never weaker (the owner's)` for its own `agentAccess`). A caller with no login from a folder registered to no project (Global, `list` only — the person's own CLI without a login looks the same) can still read, and can no longer change any setting; the person changes them with their login.

**What this costs, said plainly.** A model scoped to a project can no longer change a vault-wide setting for the user (dark mode, the auto-lock): it gets `capability_not_held` and the KB tells it to ask the user to make the change in CredMgr or with their own login. That is the price of "never Global unless its scope is Global". The KB (`docs/LLM_KB.md`) is regenerated with the rule and an example of each answer.

**Tests.** `crates/brokerd/tests/isolation.rs` I-32 through the real server wiring from working folders: `i32a_an_agent_with_no_access_reads_and_changes_no_setting_and_files_no_request` (every read, write, revert and request poll refused; no request filed; every policy byte-identical), `i32b_an_agent_changes_settings_only_of_its_own_node` (own project and own sub-node apply; Global's node setting, a stricter, cosmetic and weaker vault setting, the parent, a shared sibling refused with `update`; an unreachable project `not_found`), `i32c_an_agent_never_files_a_request_that_raises_its_own_access` (a read-only agent asking for `read-write` is refused and nothing is queued; a read-write agent's weakening change to its own project still waits); `crates/brokerd/tests/switchboard.rs` (vault-setting agent cases now use an agent whose scope is Global; `an_agent_never_asks_for_more_of_its_own_access`, the backstop); `crates/brokerd/tests/agent_tokens.rs` (a token confined to its node is refused a vault setting; its own node's weakening change waits and names the token); `crates/cli/tests/mcp_integration.rs::the_switchboard_end_to_end_from_a_real_mcp_client` (a project agent is refused `app.theme`; its own project's weakening change is approved by the owner through the real CLI); `scripts/endpoint-matrix.py` §8d (a project agent refused a vault setting and Global's node setting, its own project's weakening change pending).

## ADR-156 · The post-launch quick wins: passphrase change, expiry, history, node search, lookup by reference, the anomaly alarm, start at login, the airlock check, I-10, and five hardening items (2026-11-09)

**Context.** The operator (live chat, 2026-11-09) answered the 2.x list of ADR-153 §4 and `research/2026-11-08/01_POST_LAUNCH_QUICK_WINS.md` with "Start the quick wins". The batch is items 4–13 and 15–19 of that list. Item 14 (notes as MCP tools) is left out: it reverses ADR-072's capability-only stance and needs the operator's call. Signing, notarisation, publishing, licensing and sync are not in it. The rule carried over from ADR-155: nothing here weakens an existing control, and every change that could weaken one goes through the owner's step-up.

**Decision.**

1. **Seven broker ops** (84 → 91), none of them MCP tools (still 21), no new error codes. Every one is bridged in the app (91 commands) and has a CLI form.
   - `vault.set_passphrase` (owner, admin). A root rotation (ADR-076) whose new passphrase wrap comes from the new passphrase, so it inherits that op's staging, commit and crash recovery. It needs the current passphrase, a second factor where one is enrolled, and a presence proof where a presence key is enrolled (with none, the current passphrase is enough: a Mac without Touch ID, a Linux machine). It shares the unlock backoff, answers a new recovery code once, and its audit record carries neither passphrase. A crash before the commit keeps the old passphrase; after it, the new one. CLI `credmgr passphrase` (both passphrases on stdin, never argv). App: Settings › Security › "Change passphrase".
   - `entry.set_expiry` (capability: `update` on the node), a dedicated op rather than an `expiresAt` parameter on create and update as the research note suggested: an expiry is manifest metadata, so it needs no envelope rewrite, carries the entry's generation (a stale one is refused), and clearing takes an explicit `clear: true` so an omitted field can never erase it. CLI `credmgr expire`.
   - `entry.expiring` (human only, ADR-077 §5: expiry and rotation dates are not shown to agents). Lists entries expiring within a window, already-expired ones marked. CLI `credmgr expiring`.
   - `entry.history` (human only, same reason). The entry's create, update, rotate and expiry decisions from the audit log, in order, with no value. A create now shows there because the server records the answer's `entry` id when the request named none. CLI `credmgr history`.
   - `entry.search` (capability: `list` on the node). Names and aliases on one node, never values or labels (K-10 (c) stands: searching values would need a plaintext index). CLI `credmgr search --node`.
   - `entry.get_by_ref` (capability: `list`). Resolves an entry's vault-global short reference number (wire key `reference`) to its node, id and name, among the entries the caller could already list, and answers `not_found` otherwise, so it confirms nothing a list would not (I-3). CLI `credmgr ref`.
   - `vault.anomalies_ack` (owner). See item 2.
2. **The anomaly alarm reaches the owner.** The cross-node anomaly (I-16: five cross-node denials in ten minutes) already tripped and was audited; nobody was told. `vault.status` now carries `anomaliesUnseen` for the owner's login only; `vault.anomalies_ack` resets it. App: a notice bar (Open audit, or ✕ to dismiss). CLI: `credmgr status` prints the count, `credmgr status --ack` clears it.
3. **Start at login (macOS).** The app installs a per-user LaunchAgent (`~/Library/LaunchAgents/com.credmgr.brokerd.plist`, absolute `credmgrd` path looked for beside the app, then `/usr/local/bin`, then `/opt/homebrew/bin`), loaded with `launchctl bootstrap gui/$UID` and removed with `bootout`; never root, idempotent. Settings and the boot screen's "broker not running" state offer it; turning it off asks first, since it stops the broker. Other platforms answer `platform_unsupported`. Three hand-written shell commands (17).
4. **Touch ID row without a Secure Enclave** stays visible and disabled, with one line saying whether the vault is protected by the passphrase only or the passphrase plus Touch ID on this Mac.
5. **Confirm before showing secrets covers `search.content` and `notes.read`** (closes K-24's first half). With the setting on, a person's content search is gated as a critical value and a note read as a high one, before any value is read or a rate slot spent. Agents are not asked, as for a reveal. Non-reads stay ungated (ADR-150's scope).
6. **Hardening.**
   - **K-9, closed.** `audit::append` still writes every record but signs a new tip only when the current tip verifies under the root key and names the log as it stands, or lags it by exactly the one line a crash between the two writes leaves. A truncated or emptied month, a missing tip, or one signed under another key now stays visible to `credmgr verify` after later requests. The root rotation's `notResigned` caveat goes. Residual: a same-user attacker can still append one chained line, which the crash allowance accepts.
   - **K-10 (a), closed.** One request line is read under a 128 MiB cap (twice the 64 MiB batch limit, not the research note's 1 MiB, which a 500-entry batch exceeds) and a connection that overruns it is closed. The line buffer and every string the parsed request held are zeroised before reuse (this also wipes the export passphrase copies, K-23 (b)).
   - **K-10 (e), closed.** Retained entry generations are pruned: one is dropped only when it is outside the entry's 20 most recent **and** older than the seven-day field-undo window. Unverifiable snapshots are kept for `verify`. Pruning is best effort and never fails the change it follows. An undo older than both answers `not_found`.
   - **K-23 (a), closed.** The desktop shell, like the CLI and broker, honours `CREDMGR_PRESENCE_HELPER` only in debug builds.
   - **K-23 (d), closed.** `credmgr restore` refuses while a broker answers on the vault's socket, before the passphrase is read; a socket nobody listens on does not block.
   - **mlock (item 18).** Each hot node key sits on its own page-aligned page, `mlock`ed and on Linux `MADV_DONTDUMP`, zeroised in place on lock and again on drop before `munlock`. A refused `mlock` (a low `RLIMIT_MEMLOCK`) is counted and said once on stderr, never fatal. `locked_key.rs` carries the crate's third scoped `allow(unsafe_code)` (beside `peer.rs` and `state/rotate/vault_lock.rs`): no safe wrapper exists in the MSRV's standard library and the crate takes no new dependency for it.
7. **The airlock is gated (item 9).** `scripts/airlock-check.sh` proves A-1 (the binary carries no TCP/UDP socket type, HTTP or TLS stack, symbol scan plus dynamic libraries) and A-2 (the real `credmgrd`, started on a throwaway vault and driven through init, unlock, a write and a read, holds no internet socket at either moment; the detector first proves it sees a known listener). CI job `v2-airlock` in `security.yml` on pull requests, and `gates.sh`.
8. **I-10 is tested (closes K-1).** Presence is reachable since ADR-098, so the positive half is now written: a sealed node's names stay listable to the orphan view with no value, an agent and a proof-less or forged-proof call are refused, a valid proof opens the value and a replay is refused, and `access::resolve` allows orphan reads for native-with-presence only, over every origin. 28 of 28 isolation tests. I-20, I-21 and I-23's positive halves stay open.

**Not done in this batch, and why.** The desktop expiry chip on an entry and the entry History tab (the ops, CLI and bridge are built; the screens are a front-end pass). Item 14 (operator's call). Bundling `credmgrd` inside the `.app` (the login agent looks for it beside the app; packaging is release work). The macOS `launchctl` path was written and unit-tested off macOS and is not yet exercised on a Mac (`RELEASE_VERIFICATION.md` rows added, not pressed).

**Alternatives rejected.** `expiresAt` on `entry.create`/`entry.update` (an omitted field would read as "clear", and an expiry change would rewrite the envelope); making `entry.history` and `entry.expiring` agent-readable (ADR-077 §5 keeps those dates human-only); a 1 MiB request cap (breaks legitimate batches); signing over any tip after a crash (re-opens K-9); an extra dependency for `mlock` (the crate's dependency budget; three syscalls do not justify it); a `pidfile` check for restore (a stale file blocks; a socket that answers is the fact that matters).

**Tests.** `crates/brokerd/tests/set_passphrase.rs` (6); `crates/brokerd/tests/quick_wins.rs` (9: expiry set, listed and cleared, already expired, refusals, agents, restart; history order and denial; node search; references); `crates/brokerd/tests/isolation.rs` (`i10_…` new, `i16_…` now asserts `anomaliesUnseen`); `crates/brokerd/tests/reveal_confirm.rs::a_content_search_and_a_note_read_ask_like_a_value_does`; `crates/store/src/audit.rs` (`a_truncated_tail_is_not_signed_over_by_the_next_append`, `a_tip_one_line_behind_after_a_crash_is_signed_forward`, `a_tip_signed_under_another_key_is_not_signed_over`) and the flipped `rotate_root.rs` test; `crates/store/src/rotation_history.rs::prune_keeps_the_latest_and_the_recent_and_drops_only_what_is_both_old_and_beyond_them`; `crates/brokerd/src/server.rs::a_request_line_over_the_limit_is_cut_off_and_one_at_the_limit_is_read`; `crates/cli/tests/restore.rs::a_restore_is_refused_while_a_broker_answers_and_reads_no_passphrase`; `crates/brokerd/src/locked_key.rs` (2); `scripts/airlock-check.sh`; the desktop drift guards (91 bridged commands, 17 shell commands) and `tests/unit/quick-wins.test.ts`.

**Amendment (ADR-165 N5, 2026-11-20).** `vault.set_passphrase` now also gives every live node a new keypair and re-seals what it holds, in the same rotation stage and under the same commit record, so a copy of the folder from before the change plus the old passphrase opens nothing written after it. The answer gains `nodesRekeyed` and `filesResealed`; the op becomes O(entries). See ADR-165's fourth addendum.

## ADR-157 · The quick wins left for the app: the expiry chip and dialog, the History tab, and `credmgrd` inside `CredMgr.app` (2026-11-12)

**Context.** ADR-156 built the broker, CLI and bridge halves of quick wins 3 (expiry) and 4 (history) and the start-at-login agent, and left three things for later: the desktop expiry chip, the entry History tab, and bundling `credmgrd` in the `.app` (the login agent looked for it beside the app, then `/usr/local/bin`, then `/opt/homebrew/bin`, so an app user without the tarball had nothing to start). The operator asked on 2026-11-12 to build the deferred items. Item 14 of the quick-wins list (notes as MCP tools) stays out: it reverses ADR-072 and is the operator's call. No broker op, MCP tool, error code or CLI command is added (still 91, 21, 27, 45); the bridge already carried `entry_set_expiry` and `entry_history`.

**Decision.**

1. **Expiry chip and dialog.** The entry detail shows, under the name, a chip with the stored expiry (`entry.get` already answers `expiresAt`, so the chip costs no call): grey later than 30 days, amber within 30 (the broker's own `entry.expiring` window), red once passed, counted in whole UTC days. A "Set expiry…" / "Change expiry…" button opens a dialog (`dlg-expiry`): a `YYYY-MM-DD` box, presets of 30, 90 and 365 days, Remove expiry when one is set. **A date is a calendar day in UTC and means the start of that day**, exactly as `credmgr expire --at` parses it (`quick_cmds.rs parse_at`), so the app and the CLI never disagree by a time zone. Save sends one `entry.set_expiry` with the node's generation and the date, or `clear: true` with no date; the entry is then read again (no optimistic write), and a stale generation re-reads the entry and keeps the dialog for a second Save, as every other vault write does. A date already begun is allowed with a warning (the CLI allows it too). Nothing is locked or deleted when the day passes.
2. **History tab.** The entry detail gets Fields and History tabs; Fields is the default and the tab belongs to the entry (another entry opens on Fields). History calls `entry.history` once with `limit` 200 (the broker's default is 100, its maximum 500) and lists the records newest first with the time, the action in words (an unknown action as the broker named it), the actor (`human` reads "you"; an agent's public session id as given) and "refused" for a denied decision, plus the entry's last change, rotation and expiry. A refusal is said in words and offers Try again; it is never shown as an empty trail. A lock, a locked node, a lost login or a stopped broker goes to the app's own screens. A change made from the detail while the tab is open reads the trail again. The op is human-only (ADR-077 §5) and returns no value, so nothing new is exposed.
3. **`credmgrd` inside the app.** `tauri.conf.json` `bundle.macOS.files` copies `target/release/credmgrd` to `Contents/MacOS/credmgrd`, the first place the login agent looks (`login_agent::daemon_candidates`). `scripts/release-app.sh` builds it first, with the same commit stamp, path remap and `MACOSX_DEPLOYMENT_TARGET=13.1` as `release.sh`; the release verifier (`release-lib.sh`) refuses an app without it, with a build-machine path, without exactly one build stamp, from another commit, from a dirty tree (outside a `--dev` build) or above the minimum macOS; `release-selftest.sh` proves the refusal (`app-no-daemon`); `scripts/sign-notarise.sh` signs it inside-out with the presence helper before the app. The tarball still ships its own `credmgrd`, built from the same commit with the same flags.

**Alternatives rejected.** A date-and-time picker or local-time dates (the CLI and the broker's window are UTC days; two meanings of one date is the bug to avoid); showing history in the node's audit view only (the quick-wins note and the CLI are per entry); fetching history with every entry open (it reads the whole audit range; on demand is cheaper); an `SMAppService` login item or `Contents/Library/LaunchAgents` plist (the Mac App Store path, ADR-153 / research 04, not the Developer ID edition; the per-user agent of ADR-156 stays); pointing the agent at the tarball's install location only (an app-only user has none).

**Not done, and why.** The new screens and the `launchctl` path are tested against the fixture broker, in the shell's tests and in the release self-test, **not pressed in a built app** (needs the operator's Mac; `RELEASE_VERIFICATION.md` rows marked not pressed). Signing waits on the operator's Developer ID (K-A). Notes as MCP tools (operator's call).

**Tests.** `apps/desktop/tests/unit/history-expiry.test.ts` (16: UTC day parsing and refusals, chip tones, Set/Change/Remove with exact bridge arguments, presets, stale generation, a gone entry, History read once with its limit, refresh after a change, refusal and retry, tab per entry); fixture broker `tests/fixtures/broker/quick.js` with `entry_set_expiry` and `entry_history` examples checked by `fixture-shape.test.ts`; four new design states in `scripts/states.mjs`; binding count 779 → 825; `src-tauri/tests/shell_config.rs::the_app_bundles_credmgrd_where_start_at_login_looks_first`; `scripts/release-selftest.sh` case `app-no-daemon`; `RELEASE_VERIFICATION.md` §2 (14 rows, `dlg-expiry`).

## ADR-158 · `entry.move`: move an entry to another node, re-sealed to that node's key, in one crash-safe step (2026-11-14)

**Context.** Item 14 of the post-launch quick-wins list (`research/2026-11-08/01_POST_LAUNCH_QUICK_WINS.md`) and the planned row 99 of `18_ENDPOINT_INDEX.md`. Today an entry filed under the wrong node can only be copied by hand (reveal, create, remove), which shows the value, loses its id, reference, aliases and expiry, and leaves both copies readable in between. The doctor's tidy-up scan (item 15) needs a move to propose for "misfiled" entries. An entry's envelope is sealed to its node's key with the node and entry ids in the AAD, so a move must re-seal it; and the loader accepts a manifest one generation ahead of the registry as an interrupted write, so writing the two manifests one after the other could, after a crash between them, leave the entry in both nodes or in neither.

**Decision.**

1. **The op.** `entry.move {node, entry, to, generation, reason?}` answers `{node: to, entry, ref, name, from, generation, toGeneration, grantsRevoked, historyDropped, cleanupWarning?}` and never a value. `generation` is the source node's (optimistic concurrency, `conflict` when stale, checked before any factor so a stale request costs no finger); the answer's `generation` is the source's after the move and `toGeneration` the destination's, which the next change to the moved entry echoes. The entry keeps its **id and its vault-global reference**, so `entry.get_by_ref` and anything holding the id find it in its new node. `reason` (1–500 characters) is free text for the doctor's `doctor:<plan>` tag; it goes into the audit record's detail only.
2. **Who may call it.** The owner's login only (`owner_session`): an agent session, an agent token or a cwd-scoped process is refused whatever its scope, `Admin` included, so no agent can carry an entry out of its scope or into another. `Admin` on **both** nodes. MCP never offers it (`FORBIDDEN_OPS`), and there is no MCP tool.
3. **Gates: the stricter of `node.rekey` and `entry.remove`, which is `node.rekey`'s.** A fresh second factor for the vault and for each node that has its own (`require_fresh_factors_for` on both ends), and a presence proof (Touch ID) on **every** call (`PRESENCE_EVERY_TIME`; the factor window is not consumed, as with `node.rekey`). A vault with no presence key enrolled answers `presence_required` as every presence-gated op does. The request takes the exclusive barrier in `server.rs` (like `node.rekey` and `maintenance.rotate_root`), so no other request runs during a move.
4. **What travels, what does not.** The name, aliases, expiry, fields, type, sensitivity and rotation time travel in the manifest row (`modified` becomes the move's time). **Name collisions are refused, not renamed:** the entry's name or any alias meeting a name or alias in the destination, or a name waiting in the destination's locked-write tray, compared without case as `entry.create` does, is `entry_exists` and nothing moves. **Grants on the entry are revoked** in the same commit (a grant names its node and entry, so carried over it would grant the wrong node's entry; re-granting is one `grant.create`); grants on either node as a whole are untouched, so agents of the source lose the entry and agents of the destination gain it. **Rotation history (`entry.undo`) is destroyed**: the retained old values are sealed to the source's key and keyed by node, so after the commit the source's `archive/entry-history/<from>/<entry>` is deleted and the count is returned as `historyDropped`. **Node notes stay** with their node (they are per node, not per entry). An agent approval waiting on the old address is discarded (its staged value would release nothing).
5. **Crash safety: never both copies readable, never lost.** `state/move_entry.rs` stages, under `move-pending/<entry>/`, copies of **both manifests as they are now** and a plan sealed under the root key (generations, manifest and envelope hashes), then writes the re-sealed envelope at its destination path (unread: no manifest names it yet). The commit is **one registry write** that binds both new manifest generations together. On every load `verify_registry_and_rest` settles a leftover stage against the registry: both bindings past the plan rolls **forward** (deletes the source envelope and history if the committed source manifest lacks the entry); both bindings equal to the plan rolls **back** (restores both staged manifests and deletes the destination envelope if its hash is the plan's); anything else removes the stage. A plan that does not open is a corrupt-vault error, never a guess. An in-process failure before the commit restores memory and disk and answers `internal` ("rolled back"); one after it finishes the move, and a stage that cannot be removed is reported as `cleanupWarning` and removed at the next unlock.
6. **Audit.** The generic per-request record names the **source** (`params.node`, the source's generation, "reason: …" when given); an item event `entry.move` names the **destination** with detail `moved from <source>`; each revoked grant gets a `grant.revoke` item event. `entry.history` follows the `moved from` chain back through the nodes the caller may list, so the moved entry's history shows its life in every node, each row naming its node.
7. **Refusals with existing codes (the 27 stay):** the same node and the orphan node `malformed_request`, a node or entry that is not there `not_found`, a caller that is not the owner's login, or without `Admin` on both nodes, `capability_not_held`, a locked node at either end `node_locked`, a stale generation `conflict`, a name clash `entry_exists`, an in-memory vault `malformed_request` (moves are durable only).
8. **Surfaces.** CLI `credmgr move <name> [--node <id>] --to <id> [--reason <text>] [--json]` (46 commands); desktop bridge `entry_move` (92 bridged commands) with `entry.move` in `AUDIT_PASSTHROUGH`; the entry inspector's **Move to project…** opens `dlg-move` (destination picker of the other open nodes, what does not travel said before the press, the counts said after it), and the inspector follows the entry to its new node.

**Alternatives rejected.** Carrying grants over (a grant addresses node and entry; moving it silently re-points access the owner granted for another node); re-sealing retained history to the new key (it is undo for the old node; a move is not undone with `entry.undo`, it is moved back); renaming on collision (silent renames break `.env` references); allowing agents with `Admin` on both nodes (the brief and ADR-077 keep scope changes human); a new `move_conflict` error code (`entry_exists` and `conflict` say it); two manifest writes without a stage (the one-ahead tolerance makes a crash between them ambiguous); minting a new id (would break references and the doctor's proposals).

**Not done, and why.** The desktop control is tested against the fixture broker and the shell's bridge tests, **not pressed in a built app** (`RELEASE_VERIFICATION.md` rows "not pressed — new in ADR-158"). The doctor's "misfiled" proposals that call it are item 15's work.

**Tests.** `crates/brokerd/tests/entry_move.rs` (18: success with restart, `get_by_ref` and a move back; aliases and expiry travel; stale generation; agents and non-login scopes refused; same node, orphan, missing node, locked node, missing entry; name and alias collisions; second factor then presence then a swapped proof; grants revoked and kept, across a restart; history across the move; the crash table AfterStage / BeforeRegistry roll back, AfterRegistryBeforeCounter / AfterCommit roll forward; one manifest written never leaves two copies; in-process rollback; a stage left behind; a tampered plan refuses unlock); `crates/cli/tests/quick_cmds_cli.rs::move_refuses_usage_mistakes_and_without_presence_moves_nothing`; `src-tauri/tests/bridge_ops.rs` (sweep and frames) and `drift_guards.rs` (92 arms); `apps/desktop/tests/unit/entry-move.test.ts` (10); fixture broker `quick.js` `entry_move` with examples; binding count 825 → 839.

## ADR-159 · A diagnostic log with no names or values (2026-11-14)

**Context.** Post-launch quick win 19 (`docs/research/2026-11-08/01_POST_LAUNCH_QUICK_WINS.md`) and `16_CROSS_PLATFORM.md §6.1`: `paths.rs` had no log directory and the broker wrote no log file, so a crash or a refusal left nothing a person could send with a bug report. §6.1 sets the rule a diagnostic log must keep: users will paste it into a bug report, so it holds no entry names, no node names and no values. The operator asked on 2026-11-14 to build it. No broker op, MCP tool, error code or CLI command is added (still 91, 21, 27, 45); `credmgr status` gains one flag.

**Decision.**

1. **Where.** `credmgr_store::paths::default_log_dir()`: `CREDMGR_LOG_DIR` overrides; else `~/Library/Logs/credmgr` on macOS, `%LOCALAPPDATA%\credmgr\logs` on Windows, `$XDG_STATE_HOME/credmgr/logs` or `~/.local/state/credmgr/logs` elsewhere (the §6.1 table). Outside the vault, so a backup never carries it and deleting it loses only history. The desktop shell mirrors the table in `vault_paths.rs::log_dir_from`, held to `paths.rs` by `drift_guards.rs::the_log_dir_rule_still_matches_crates_store`.
2. **What a line holds, by construction.** `crates/brokerd/src/diag_log.rs`: `<UTC timestamp> pid=<n> event=<kind>` and fields whose values are a `&'static str` or a number. There is no variant for a runtime string, so a name, a value, a note, an alias, a path, a token or a request body cannot be passed to it; the compiler refuses. The op of a request is the caller's text, so it is logged only as one of the broker's own dispatch labels (`KNOWN_OPS`, held to `ops.rs`'s dispatch table by a unit test) or as `unlisted`. A failure is logged by its static wire code (`server::error_tag`), never by the error's message, which can quote a name. A panic is logged by line and bare `*.rs` file name only (a full path would carry the build machine's home directory; the panic message is never written).
3. **What is logged.** Start (version, commit, dirty, OS, architecture, whether the vault directory is overridden, whether a vault exists), the start-up rotation recovery's outcome, listening, exit with a reason code, one line per request (`op`, `result` = `ok` or the error code, `ms`), framing errors (`too_long`, `not_utf8`, `not_json`), refused peers, and panics. A token-less `vault.status` or `vault.approval_get` that succeeded is skipped: the Lock screen asks every five seconds, and those lines would push everything useful out of the cap within a day.
4. **Size.** `credmgrd.log`, rotated to `.1` and `.2` at 1 MiB: 3 MiB at most. The directory is `0700`, each file `0600`. A write that fails is dropped; the log never fails a request.
5. **Off by default.** The broker writes nothing unless `CREDMGR_DIAG_LOG=1` (or `true`, `on`) is in its environment. Name-free is not activity-free: one line per request is a timeline of when the vault was used, kept outside the encrypted vault, in a folder macOS diagnostic bundles collect. The more private choice is to keep it off until someone is chasing a problem. On macOS `launchctl setenv CREDMGR_DIAG_LOG 1` before starting the broker (or the app) turns it on for both; elsewhere it is set in the broker's environment.
6. **The desktop shell.** `apps/desktop/src-tauri/src/diag_log.rs` writes `desktop.log` in the same directory under the same switch and rules: a start line and one line per broker call, with the op's label from the bridge's own table and the error's static code (`code_label`), never params, values or messages.
7. **Finding it.** `credmgr status` ends with `diagnostic log: <path> (…)`; `credmgr status --log` prints only that line and does not ask the broker, so it works when the broker will not start. It says whether a log has been written and, if not, how to turn it on.
8. **No network.** A file in a local directory; nothing is uploaded and nothing reads the log back.

**Alternatives rejected.** On by default (useful for a first crash, but a usage timeline written outside the vault without being asked for); a switchboard setting (the broker needs the answer before unlock, when the vault's settings cannot be read, and a new setting is a catalogue change for one switch); logging the op string as sent (a caller can put anything in it, including a value); logging error messages (several quote an entry or node name); a `credmgr logs` command (a flag on `status` answers "where is it" without a 46th command); a logging crate (`tracing`/`log` accept arbitrary strings, which is what this design exists to rule out).

**Not done, and why.** The launchd agent (ADR-156) already sends `credmgrd`'s stdout and stderr to `brokerd.log` and `brokerd.err.log` in the same macOS folder; those are not this log, are not size-capped, and carry the vault path (and so the user name) in lines such as "listening on …". Making them name-free changes messages the CLI and the release scripts read; it is left as a follow-up. A broker killed by a signal writes no exit line (there is no signal handler). Windows has no broker transport yet (§5.3), so its row is resolved but has never run.

**Tests.** `crates/brokerd/tests/diag_log.rs`: (1) a sample of real ops through the real server wiring, successes and failures, whose requests carry entry and node names, a value, a note, an alias, an `otpauth://` seed, a wrong passphrase, a dead token and an unknown op named like a secret, plus a panic whose message holds a value; every file in the log directory is read and none of those strings, the session token, the entry ids, the workdir, the vault directory or `$HOME` appears, every line parses as plain `key=value` tokens, and the useful lines (`op=entry.create result=entry_exists`, `op=vault.unlock result=wrong_passphrase`, `op=unlisted result=malformed_request`, `event=panic … file=diag_log.rs`) are there; (2) the real `credmgrd` binary started without the switch creates no log directory, and started with it writes start, recovery, listening, request and framing lines and none of the strings sent over the socket. `diag_log.rs` unit tests: UTC timestamps, unknown ops never echoed, panic file names, rotation at the cap keeping three files, `0700`/`0600` modes, `KNOWN_OPS` equal to the dispatch table. `paths.rs::the_log_dir_is_never_the_vault_and_its_override_wins`. `cli/tests/broker_integration.rs::status_log_names_the_log_file_without_a_broker`. Shell: `diag_log` unit tests (labels never echo caller text, rotation), `vault_paths` log tests, the new drift guard.

**Amendment (2026-11-20) · the launchd agent's output files.** The "Not done" item above on `brokerd.log` and `brokerd.err.log` is closed.

1. **The agent keeps no output files.** `login_agent.rs::render_plist` (and both packaged templates, `crates/brokerd/packaging/` and `v2/packaging/`) point `StandardOutPath` and `StandardErrorPath` at `/dev/null`. launchd never rotates a redirect target, so capping a file it owns was not possible; the record is the diagnostic log above (1 MiB, three files, name-free, switched on with `CREDMGR_DIAG_LOG=1`). Rejected: a capped log written by the broker itself for its stdout (a second log with its own rules next to a first that already exists), and a size-trimming job (a new moving part to protect a file nobody needs).
2. **The daemon's own messages are name-free anyway.** No start-up, recovery or shutdown line prints a path: the vault, state, log and run folders and the socket are named by a fixed phrase ("the vault folder", "the broker socket"), and an I/O failure by its kind (`main.rs::kind_label`), never its text. The ADR does not allow substituting `~` for the home directory (a path with the home replaced still reveals the layout), so there is no path form at all. The token `listening on` is kept (`tests/rotate_root.rs` waits for it); it now reads `credmgrd: listening on the broker socket`. A foreground run in a terminal loses the socket path it used to print; `credmgr status` still prints it.
3. **Older installs.** The agent file differs from what the app now renders, so the app's own check reports it as not current and the next "Start at login" install rewrites it; that install also deletes the two files earlier builds left in `~/Library/Logs/credmgr` (exactly `brokerd.log` and `brokerd.err.log`, nothing else in the folder).
4. **Tests.** `tests/startup_output.rs` runs the real `credmgrd` in a temporary home: no start-up line holds the home directory, a folder name, the socket name or the user name, `listening on` is present, and a second broker on one vault refuses without naming the socket. `login_agent.rs`: the rendered agent sends both streams to `/dev/null` and names no home folder; `remove_legacy_logs` removes the two files and leaves `credmgrd.log` and `desktop.log`.
5. **The exit line on a signal: not done.** Needs `unsafe` or a new dependency (signal-hook); low value. `crates/brokerd` holds `unsafe_code = "deny"` with one scoped allow in `peer.rs`; neither tokio nor signal-hook is in `Cargo.lock`, and a handler through `libc::signal` is `unsafe`. A broker killed by SIGTERM or SIGINT still writes no exit line, which the start line, the last request line and the missing exit line already say.

## ADR-160 · Reading an authenticator QR-code image in Add entry (2026-11-14)

**Context.** Post-launch quick win 20 (`docs/research/2026-11-08/01_POST_LAUNCH_QUICK_WINS.md`): a TOTP seed could be added only as text or a pasted `otpauth://` URI, while most sites show it as a QR code. The quick win named the constraint: the decoder must be bundled, because the desktop CSP forbids remote scripts. The operator asked on 2026-11-14 to build it. No broker op, MCP tool, error code or CLI command is added (still 91, 21, 27, 45); the broker and the shell's Rust code are unchanged apart from one window setting.

**Decision.**

1. **Where.** The Add entry dialog (`S6-add-entry.html`) gets a "2FA QR" area under "+ Add field": drop a PNG or JPEG on it, or choose one with a file picker (`accept="image/png,image/jpeg"`). The decoded URI goes into the first empty value box, or a new field if none is empty, exactly as if it had been pasted. From there the existing path takes over: the shell's field preview types it `totp-seed`, and saving stores it through `entry.create` as today. Nothing is saved until the person presses Save.
2. **The decoder.** `jsQR` 1.4.0 (Apache-2.0, pure JavaScript, no dependencies), pinned exactly in `apps/desktop/package.json` with its registry integrity hash in the lockfile, bundled by Vite into the app. It is an npm dependency rather than a copied file so that the dependency audit and the supply-chain scanners see it and its licence appears in `THIRD_PARTY_NOTICES.md`; it makes no network call.
3. **Reading the file.** `src/vault/qr-import.ts`. The file is refused before it is decoded if it is empty, larger than 8 MiB, or does not start with a PNG or JPEG signature (the file's own type is not trusted). It is read into an `ImageBitmap`, scaled so its longer side is at most 2048 px, drawn on a canvas that is never attached to the page, and read once. Only `otpauth://totp/…` or `otpauth://hotp/…` of at most 4096 characters with no control characters is accepted; any other QR content is refused with "That QR code is not an authenticator code", and its text is not shown.
4. **Leaving nothing behind.** No object URL, no `data:` URL and no `<img>` is made. After decoding, whatever the outcome, the pixel buffer and jsQR's byte copy are overwritten with zeros, the canvas is cleared and shrunk to 0 × 0, the bitmap is closed, and the file input's value is emptied. Nothing writes to the console, storage or the network. An error carries only a code from `QrImportCode` and a fixed sentence, never what the image held. A JavaScript string cannot be wiped, so the decoded URI lives in memory until collected, exactly as a pasted one does. If the dialog closes while an image is being read, the result is dropped.
5. **File drops.** Tauri's own drag-and-drop handler is turned off for the main window (`"dragDropEnabled": false` in `tauri.conf.json`) so that an HTML drop reaches the page; `main.ts` cancels `dragover` and `drop` everywhere else so a file dropped outside the area is not opened by the webview. The shell gains no file-reading command.

**Alternatives rejected.** Copying the decoder into the repository (the brief's word was "vendor"; a copied file escapes `npm audit` and the scanners, which matter more for a component that parses untrusted input); a native decoder in the shell (a new command that takes a file path and returns a seed across the bridge, more surface for the same result); `BarcodeDetector` (not available in WebKit, which the macOS and Linux shells use); a camera scanner (a new permission and a new attack surface; a screenshot does the job); decoding in the broker (the broker takes no images and has no reason to).

**Not done, and why.** HOTP URIs are accepted as a value but stored as today, with no counter handling. Google Authenticator's `otpauth-migration://` export (several seeds in one code) is refused as "not an authenticator code"; it is a separate format. The drop area and file picker, and the `dragDropEnabled` change, have not been pressed in a built app (`RELEASE_VERIFICATION.md` rows added, marked not pressed). `npm run test:csp` could not run here (no Playwright WebKit).

**Tests.** `apps/desktop/tests/unit/qr-import.test.ts` (18): QR images generated by `tests/fixtures/qr/make-fixtures.mjs` with an obviously fake secret (`FAKESECRETFORTESTSONLY22`, issuer "CredMgr Fixture"); the seed image decodes to the exact URI; a non-authenticator code, a blank image, a non-image, an oversized file and an unreadable image are each refused with their code and nothing of their content; the pixel buffer is zero, the canvas is 0 × 0 and the bitmap closed after success and after failure; through the logic layer and the fixture broker, a chosen file fills the field, the preview types it `totp-seed`, no `entry.create` is sent and nothing is written to the console; a drop does the same; a result arriving after the dialog closed is dropped, and closing wipes it; source guards (no console, storage, fetch or object URLs in the module); the template wiring; the lockfile pins jsQR with its integrity. `src-tauri/tests/shell_config.rs::the_main_window_leaves_file_drops_to_the_page`. Template bindings 825 → 832 (`logic.test.ts`, `compile.test.ts`).

## ADR-161 · `vault.doctor_scan`: the doctor's tidy-up scan, phase 1: a read-only report with a preview plan whose moves apply one at a time through `entry.move` (2026-11-14)

**Context.** Item 15 of the post-launch quick-wins list (`research/2026-11-08/01_POST_LAUNCH_QUICK_WINS.md`), research memo 03 §3, doc 25 and plan 26 §7. A vault that has grown by hand holds the same value in several places, near-identical names, entries filed in Global that belong to one project, weak or mistyped values, and entries that expired or were never rotated. The owner can find none of these without revealing values one by one. `maintenance.doctor` already exists and checks the vault's own health (files, registry, keys); it is not about the owner's entries and stays as it is. ADR-158 built `entry.move` so the scan has a safe way to apply a "misfiled" proposal.

**Decision.**

1. **The op.** `vault.doctor_scan {staleDays?, expiringDays?}` (each 1–3650; defaults 365 and 30) answers `{now, staleDays, expiringDays, nodesScanned, entriesScanned, valuesChecked, skipped[], truncated, counts{}, findings[]}` and **writes nothing**. A distinct name from `maintenance.doctor`, which is unchanged. Each finding has a `kind`, the entries it is about (`{node, nodeLabel, entry, ref, name, generation}`, what `entry.list` already shows the owner), its own reason fields (field id and label, reason codes, timestamps) and, where plan 26 §7 has one, a `proposal`.
2. **Who, and its gates: those of `audit.report`.** The owner's login only (`owner_session`) with `Admin` on `global`. An agent session, an agent token, a cwd-scoped process and the CLI's non-login scope are refused with `capability_not_held`, whatever their scope. This is stricter than doc 25's "an agent gets counts": no agent gets anything. No second factor and no presence proof, because nothing is revealed and nothing changes. MCP never offers it (`FORBIDDEN_OPS`), and there is no MCP tool.
3. **What is read: the checks `entry.list` applies.** A node is read only when the caller may list it, can see its names, and is not asked for a second factor to read it. The orphan node is never read. A locked node contributes nothing. **Values are opened only where the caller could reveal them without being asked for anything more:** a node with its own second factor that is not open right now is scanned by name and metadata only. Each node left out, wholly or for its values, is named in `skipped` with a reason (`locked`, `second_factor`, `not_listed`).
4. **The checks.**
   - **Shared values.** Exact duplicates, plus "probable" ones that are equal once trimmed and once a URL's scheme and host are lowercased and a default port dropped. Each value, raw and normalised, is digested with **HMAC-SHA256 under a 32-byte key drawn from the OS for this scan and dropped when it returns**. Placeholders, single repeated characters and values under 8 characters are skipped. No value, digest, length or part of a value leaves the broker, is logged or is stored. Two scans use two keys, so nothing from one can be matched against another.
   - **Near-identical names** across nodes, by `entry.similar`'s rule (`names::similar_keys`).
   - **Misfiled.** An entry in Global whose first word is exactly one project's id or label (3 characters or more).
   - **Weak passwords**, by heuristics only (shorter than 12, fewer than three kinds of character, a common word or a keyboard or repeated run). No wordlist and no network.
   - **Mistyped values.** A whole `otpauth://` URI stored as a password, or a live key prefix (`sk_live_`, `rk_live_`) in an entry or node named for testing, or the reverse.
   - **Expired and expiring** (by the entry's `expiresAt`, or a JWT's `exp` read in the broker when the entry has no expiry). The JWT `exp` is the one value-derived datum the report carries, and only when it falls inside the window. Memo 03 asks for it, and it is a date the token itself publishes, not a secret.
   - **Stale.** Not rotated (or, if never rotated, not changed) for `staleDays`.
5. **Proposals (plan 26 §7).**
   - A shared value in **two sub-nodes of one project** with no copy in that project proposes `move_to_parent`: move one copy up, then remove the others.
   - A **misfiled** entry proposes `move_to_project`.
   - Both carry `op: "entry.move"` and the exact `move: {node, entry, to, generation}`.
   - A copy already in the common ancestor proposes `remove_copies` (naming the one to keep).
   - Copies in **several projects** propose `share` (keep and grant, or use a shared node).
   - Copies in **one node**, and near-identical names, propose `merge` or `rename_or_merge`.
   - These carry `op: null`: phase 1 reports them and applies none.
   - **Every applied change is one `entry.move` the owner confirms**, with that op's own second factor and Touch ID (ADR-158).
6. **Bounds.**
   - One scan at a time: a second one is `rate_limited`, with a 5-second retry.
   - At most 10,000 entries, 10 seconds of value reading, and 500 findings of each kind. Anything cut is said by `truncated: true`.
   - The scan runs under the ordinary shared barrier, never the exclusive one, and holds the manifest lock only to copy metadata.
7. **Audit.** The generic per-request record of the op, whose params are the two day counts and nothing else. No item events.
8. **Refusals with existing codes (the 27 stay):** a bad window `malformed_request`, a caller that is not the owner's login or lacks `Admin` on `global` `capability_not_held`, a locked vault `vault_locked`, a scan already running `rate_limited`.
9. **Surfaces.**
   - **CLI:** `credmgr doctor --scan [--stale-days N] [--expiring-days N] [--json]` extends the existing `doctor` command, so there are still 46 commands. Move proposals print the `credmgr move` line that applies them.
   - **Desktop:** bridge command `vault_doctor_scan`, giving 93 bridged commands. It is not in `AUDIT_PASSTHROUGH`, because a read returns no audit id.
   - **Desktop screen:** the overlay **Tidy up** (S22). It opens from the Operations panel's "Tidy up" row and from Settings → Maintenance's "Tidy up…" button. It shows the findings grouped by kind, each with what to do, and "Move to <project>" opens the inspector's own `dlg-move` with that destination chosen. After a move from there, the scan runs again. A report lives only in memory and goes when the vault locks.

**Alternatives rejected.**
- Plain SHA-256 or a stored keyed hash. Either would let a report, a log or two reports be matched against a guessed value or against each other.
- Returning counts to agents. The brief keeps the scan human, and counts of shared values are themselves a map of the vault.
- A presence or second-factor gate. Nothing is revealed or written, and every applied change already carries `entry.move`'s gates.
- An exclusive barrier. A read has no reason to stop every other request.
- Reusing `maintenance.doctor`. Its callers and its meaning (vault health) would change.
- A new error code. The existing ones say every refusal.

**Not done: later phases.**
- Grouping a wallet's entries.
- The breach-check helper (HIBP k-anonymity, which needs network code outside `credmgrd`).
- `merge.*` (merging entries and aliases).
- A one-step "apply the whole plan" (built 2026-11-20: ADR-169, `vault.doctor_apply`).
- The undo plan.
- Applying grant or shared-node proposals.
- The desktop controls are tested against the fixture broker and the shell's bridge tests. They have **not been pressed in a built app** (`RELEASE_VERIFICATION.md` rows "not pressed — new in ADR-161").

**Tests.**
- `crates/core/src/doctor.rs`: unit tests, including that two scan keys give different digests of one value.
- `crates/brokerd/tests/doctor_scan.rs` (7):
  - every finding kind and proposal on a planted vault;
  - no value, digest or fragment in the response, the scan's audit record, the whole trail or the raw audit files;
  - agents, tokens and non-login scopes refused, and bad windows malformed;
  - a locked node contributes nothing, and a gated node only its names;
  - a move proposal applies through `entry.move`, and a rescan sees the result;
  - one scan at a time, and a capped scan says it was cut;
  - two scans agree.
- `crates/cli/tests/quick_cmds_cli.rs::doctor_scan_reports_findings_and_the_move_that_applies_them_without_a_value`.
- `src-tauri/tests/bridge_ops.rs` (sweep and frames) and `drift_guards.rs` (93 arms).
- `apps/desktop/tests/unit/doctor-scan.test.ts` (8).
- Fixture broker `quick.js` `vault_doctor_scan`, with examples.
- Binding count 839 → 853.

## ADR-162 · The Mac App Store edition: a second, sandboxed flavour beside the Developer ID build, with every identifier in one file (2026-11-14)

**Context.** Memo 04 (`research/2026-11-08/04_STORE_AND_LICENSING.md` §1.1, phase S1) and `26_PRODUCT_PLAN_2X.md` §8 recommend two editions from one codebase; plan §9 leaves the final bundle id and app-group id to the operator (decision 4). The operator asked on 2026-11-14 for everything an App Store edition needs that can be built and checked without an Apple Developer account, certificates, App Store Connect or a submission. The Mac App Store requires the app sandbox for every executable (guideline 2.4.5(i)), a self-contained bundle (2.4.5(ii)), consent before anything runs at login or after the app quits (2.4.5(iii)), and updates only from the store (2.4.5(vii)). Today's design breaks under the sandbox in four places. No broker op, MCP tool, error code or CLI command is added (still 91, 21, 27, 45).

**Decision.**

1. **Two editions, one licence system, one codebase.** The Developer ID edition stays the full-power build and its default build is unchanged byte for byte in behaviour (`entitlements.plist` stays empty, `tauri.conf.json` unchanged, `release-app.sh` without `--mas` unchanged). The Mac App Store (MAS) edition is a **compile-time flavour**: the cargo feature `mas` on `credmgr-store`, `credmgr-brokerd`, `credmgr-cli` and the desktop shell, plus the Tauri overlay `apps/desktop/src-tauri/tauri.mas.conf.json`, built only by `scripts/release-app.sh --mas` into `dist-mas/`.
2. **The identifiers live in one file**, `packaging/mas/identity.conf` (`MAS_TEAM_ID`, `MAS_BUNDLE_ID`, `MAS_APP_GROUP_NAME`, `MAS_IDS_FINAL`). The app group is `<MAS_TEAM_ID>.<MAS_APP_GROUP_NAME>` (Team-ID prefixed, so macOS 15 asks the user nothing). `crates/store/src/paths.rs` and the shell's `vault_paths.rs` `include_str!` it; `release-app.sh` renders the entitlement templates, the two embedded Info.plists and the overlay's identifier from it; `sign-notarise.sh --mas` reads it. Until the operator chooses, the values are **marked placeholders** (`XXXXXXXXXX`, the length of a real Team ID, and the current `com.credmgr.desktop`), `MAS_IDS_FINAL=no`, and `release-app.sh --mas --strict` (the submission gate) refuses them. Choosing is setting `MAS_TEAM_ID` and flipping `MAS_IDS_FINAL`.
3. **Where sandboxing breaks today's design, and the answer for each:**
   - *Broker started by a LaunchAgent the app writes into `~/Library/LaunchAgents` with `launchctl` (ADR-156)* → a sandboxed app may do neither. **Answer:** an `SMAppService` agent. Its plist ships inside the bundle (`Contents/Library/LaunchAgents/com.credmgr.brokerd.plist`, `packaging/mas/LaunchAgents/`) with `BundleProgram` `Contents/MacOS/credmgrd`, the same lifecycle keys, no log paths and no user key. `login_agent.rs` (feature `mas`, macOS) registers and unregisters it through `objc2` runtime messaging (`+agentServiceWithPlistName:`, `-registerAndReturnError:`, `-unregisterAndReturnError:`, `status`, `+openSystemSettingsLoginItems`); the page's three commands and answer shape are unchanged. **Consent:** only the existing Settings › Security › Start at login button registers it; macOS lists it under Login Items, where the user can switch it off. Because launchd is its parent, the broker cannot inherit the app's sandbox: it carries its own.
   - *Vault, socket and state directory in `~/Library/Application Support`* → outside the sandbox. **Answer:** the app-group container: `<real home>/Library/Group Containers/<group>/vault` (socket `vault/run/broker.sock`) and `<group>/state` beside it (ADR-039 still holds: never inside the vault). `$HOME` may be the app's own container inside the sandbox, so the real home is recovered lexically from `<home>/Library/Containers/<id>/Data` (`paths.rs::real_home`; the store forbids `unsafe`, so no `getpwuid`). `CREDMGR_VAULT_DIR`/`CREDMGR_STATE_DIR` still win. **The 104-byte socket limit:** the layout leaves 30 bytes for the user name with a ten-character team id and `credmgr` (`SOCKET_PATH_MAX` = 103, tested), and the inspection refuses an app-group name that breaks that budget. The drift guard reads the store's layout off disk as before.
   - *`credmgr-presence` (ADR-098)* → signed with exactly `app-sandbox` + `inherit`; it runs only as a child of a sandboxed CredMgr process and takes that process's sandbox and group. It can no longer be run on its own from Terminal.
   - *The CLI on PATH, opening any file* → **Answer:** the MAS CLI is bundled (`Contents/MacOS/credmgr`) with its own sandbox and the app group (Terminal and the apps that start `credmgr mcp` are not sandboxed, so it cannot inherit), and an Info.plist linked into the binary to give its sandbox an identifier (`packaging/mas/embedded/`; the broker gets one the same way). The user links it onto PATH themselves; the app may not write `/usr/local/bin` and must not download the full CLI (2.4.5(iv)). **Losses**, each refused by the MAS CLI with the way round before anything is asked (`main.rs::mas_limit`): `import`/`import-env <file>` (pipe it: `credmgr import-env - --node <id> < file`), `export --out <file> --age`, `restore <archive>`, `notes set --file`, and every `agent` subcommand (it reads and writes other apps' configuration files; `credmgr mcp --print-config <client>` prints what to paste). `backup` still works, but the archive stays in the group container until the app gains a save panel. The full CLI is the free separate download (Homebrew or the signed tarball), given the same team's group so it reaches the MAS broker's socket.
4. **No security property is weakened.** The broker's entitlements are `app-sandbox` and the group, nothing else: **no network entitlement**, ever (A-1; the airlock check is unchanged). The app gets no network, file-access, keychain, JIT or exception entitlement; its two identity keys (`com.apple.application-identifier`, `com.apple.developer.team-identifier`) grant no capability and are there because `codesign` does not copy them from the provisioning profile the way Xcode does. The peer gate (uid first) is unchanged. A test (`tests/mas_config.rs`) and the inspection (`rl_mas_inspect`) refuse any other key.
5. **Privacy manifest** `Contents/Resources/PrivacyInfo.xcprivacy` (`packaging/mas/`): no tracking, no tracking domains, no collected data; required-reason APIs file timestamp (C617.1: `stat`/`fstat` behind Rust's `std::fs` metadata calls, on container files) and system boot time (35F9.1: elapsed time with `Instant`, declared because the clock call may resolve to `mach_absolute_time`). Disk space, UserDefaults and active keyboards are not used and not declared. The helpers are single-file tools with no bundle, so the app's manifest covers them.
6. **Export compliance**: `ITSAppUsesNonExemptEncryption` is written into the MAS Info.plist as **`true`**: CredMgr implements standard algorithms itself rather than calling Apple's, and Apple lists that as needing documentation (the French declaration where the app is sold in France). Detail in `27_APP_STORE.md` §7.
7. **Release tooling.** `release-app.sh --mas [--strict]` renders, builds the `mas` binaries into `target/mas`, bundles the .app with the overlay (no .dmg), writes the Info.plist keys, and runs `rl_mas_inspect`; `--mas --verify DIR` inspects on any host. It signs, seals, launches and uploads nothing. `sign-notarise.sh --mas` documents the MAS signing order (profile, inside-out with each executable's entitlements and identifier, `productbuild` with the installer identity) and runs only with `--dry-run` until the operator's certificates exist. `release-selftest.sh --mas` proves 29 cases (26 refusals, 3 that must pass) on a stand-in bundle built from the real templates, on Linux.
8. **Listing, review notes and the operator's checklist** are in `docs/27_APP_STORE.md`.

**Fallback if App Review rejects the sandboxed agent.** The broker runs as a **child of the app** (inheriting its sandbox, started at app launch and stopped at quit) and the app itself becomes the login item through `SMAppService.mainApp`, optionally as a menu-bar app so it keeps the broker alive when the window is closed. Same group container, same socket, same entitlements; only `login_agent.rs`'s registration target and the app's startup change. The CLI and MCP then work while the app runs.

**Alternatives rejected.** MAS only (loses the CLI on PATH, file import and agent wiring that the developer audience relies on; memo 04 §4.5 recommends both); a runtime flavour switch (one binary that could be talked into the other edition's paths; compile time keeps the default build unable to reach any of it); the identifiers repeated in each file (a rename would be a dozen edits); `getpwuid` for the real home (needs `unsafe` in a crate that forbids it; the container shape is fixed and documented); a `network.client` entitlement for StoreKit (believed unnecessary, phase S2's spike decides; if ever needed it goes on the app, never the broker); notarising the MAS build (the store does not take notarised uploads; App Store Connect processes them).

**Not done, and why.** Nothing was built, signed, run or reviewed on a Mac (no macOS host here; certificates are the operator's). The `SMAppService` code is written against the documented API but was not compiled for macOS here. **Still blocking a submission:** the operator's ids, account, certificates, profiles and App Store Connect record (`27_APP_STORE.md` §9); the front end still shows the ADR-082 supporter code and the crypto donation addresses, which 3.1.1 forbids in the MAS build (the flavour must hide them; StoreKit Supporter purchase is phase S2); moving a vault between editions (reuse ADR-112 backup and restore through a save/open panel); `peer.rs`'s pid→cwd lookup may be refused across sandboxes (it is advisory and non-fatal; node workdir scoping would then not match); the self-integrity check (doc 21 §3, not built) must accept Apple's re-signature.

**Tests.** `crates/store` `paths.rs` (+7: flavour constant, identity parsing, compiled-in placeholder, real home, group layout, socket budget, and under `--features mas` the defaults with the override still winning); `crates/cli` `main.rs` (+3: the MAS refusals and what stays allowed); shell `vault_paths.rs` (+1), `login_agent.rs` (+2: status mapping, the bundled agent plist), `tests/mas_config.rs` (5: entitlement key sets, ids only in identity.conf, overlay contents, privacy manifest, direct build unchanged), `tests/drift_guards.rs` (+1: the group-container layout); `scripts/release-selftest.sh --mas` (29 cases).

## ADR-163 · Forgot the passphrase: the recovery code opens the vault, and the same step sets a new passphrase and a new code (2026-11-14)

**Context.** Post-launch quick win 16 (`research/2026-11-08/01_POST_LAUNCH_QUICK_WINS.md`). An owner who forgets the passphrase today cannot open the vault through CredMgr at all: the printed root recovery code is used only by `vault.gate_recover`, together with the passphrase, to reset a lost second factor (ADR-064; ADR-144 item 4 says so and names a recovery-code unlock as the prerequisite of any machine lock). The code already opens the root key cryptographically: `root.wrap.recovery` (ADR-045) is written by `vault.init_confirm` and rewritten by every root rotation (ADR-076) and passphrase change (ADR-156), and `scripts/emergency-decrypt.mjs` reads values with the code alone, offline. What is missing is a way back into the app. This is a second way to unwrap the root key through the broker, in the code that rotation, backup and the second factor depend on, so it is designed to be no weaker than the passphrase path and is reviewed as its own pull request (threat model in the PR body).

**Decision.**

1. **One op, `vault.recover {recoveryCode, newPassphrase, code?}`** (91 → 92 broker ops, still 21 MCP tools, still 27 error codes; CLI 45 → 46 commands with `credmgr recover`; bridged in the app, 92 commands: `vault_recover` is hand-written, 9 + 83, because it captures the login token as `vault_unlock` does and hands the page only the rest of the answer). A dedicated op rather than ADR-144's sketched `vault.unlock {method: "recovery"}`: the recovery is a one-way door with its own parameters and answer, and `vault.unlock`'s surface stays exactly as it was. It answers the rotation's answer plus `recovered: true`, `passphraseChanged: true`, `locked` and, when the vault is open, a login `token` as `vault.unlock` hands one out.
2. **A one-way door.** The code never leaves the vault open under itself. In the same call, the broker runs the root rotation of ADR-076 (`BrokerState::rotate_root_locked`, the code path `vault.set_passphrase` uses; `rotate_root_with` now proves the passphrase and calls it, `recover_with_code` proves the code and calls it): a new root key, a new `root.wrap.pass` from `newPassphrase`, and a new `root.wrap.recovery` under a **new** recovery code, answered once. The used code's wrap is overwritten in the same commit, and it wrapped the old root key, which nothing signed accepts any more, so a copy of it put back later opens nothing (the registry HMAC fails); the old passphrase is retired the same way. The vault becomes unlocked only after the commit and the file moves; a refusal at any step leaves it locked and every file as it was. If the rotation commits but its files cannot all be moved, the answer carries the new code with `completionPending: true` and no token, and the next unlock with the new passphrase finishes the move (ADR-076's rule). If the files are in place but the broker cannot open the node keys under the new root key, it locks the vault again (which revokes every login) and answers the same way: the new code, `locked: true`, no token (`RecoverOutcome.opened`, review P2-a 2026-11-14).
3. **Strength: no weaker than the passphrase path.** The recovery code is 256 bits from the OS CSPRNG (`recovery::generate_recovery_code`, ADR-045), above the ~128 bits this feature requires, and every recovery wrap ever written uses such a code (`parse_recovery_code` accepts exactly 64 hex digits), so there are no short legacy codes to refuse. The wrap is `HKDF-SHA512(code)` → ChaCha20-Poly1305, not Argon2id, **deliberately and unchanged**: a KDF's work factor exists to multiply the cost of guessing a low-entropy secret. Offline, the passphrase path costs 2^H(passphrase) Argon2id evaluations at m=256 MiB, t=3, p=4 (`16 §4.4`); the recovery path costs ~2^255 HKDF evaluations, which no work factor could make cheaper or meaningfully dearer. Changing the format would invalidate every printed code or need a migration path that is itself new attack surface, and buys nothing. The "same KDF strength class" requirement is met by entropy, not by the function; this is stated as a decision so a reviewer can disagree with it on the record. Online, it is behind the broker's back-off (item 5).
4. **Storage and crash safety** are the rotation's: the wrap stays `keys/root.wrap.recovery`, staged and committed with every other root-bound file under `rotation-pending/` with one atomic commit record; recovery of an interrupted rotation runs before the code's wrap is read. A crash before the commit leaves the old passphrase and the old code in force; after it, the new passphrase and the new code; never neither.
5. **Brute force: the shared per-uid unlock back-off** (`AuthBackoff`, five free failures then 30 s doubling to a 1 h cap), the same counter as `vault.unlock`, `vault.gate_verify`, `vault.gate_recover` and `vault.set_passphrase`. Shared, not separate: separate counters would hand an attacker five free guesses on each door in turn. A wrong code (`recovery_code_mismatch`, counted only for this op; for `vault.init_confirm` it still means "copied down wrong" and counts nothing) and a wrong second factor (`gate_verification_failed`) count; `two_factor_required` touches the counter in neither direction, as for the unlock; a lockout is checked before any code is read. The cost to an honest owner who has just tried passphrases is a 30-second wait.
6. **The second factor is still required when one is enrolled** (a TOTP code, or one of the gate's own printed backup codes, which is then spent and written by the rotation's registry write). The trade-off: the recovery code is a long-lived printed secret, more likely to be found in a drawer than a passphrase is to be guessed, and the owner who enrolled a second factor asked for it at the broker's door; skipping it would make the recovery door weaker than the passphrase door there. The lockout risk is bounded: the gate's backup codes exist for a lost authenticator, `vault.gate_recover` still resets a lost gate once a passphrase is known again, and `scripts/emergency-decrypt.mjs` still reads every value with the recovery code alone, so no owner loses their data to this choice. Honestly stated: the gate guards the broker's door, not the files (K-5); an attacker with a copy of the vault folder and the code never needed the broker. **Touch ID is not required and cannot be** (the point is that the owner lost access; the Mac may be new); a presence key, if enrolled, is not asked for. Review P1-2 (2026-11-14) asked for a presence proof whenever `presence_keys()` is not empty, as `vault.set_passphrase` does, on the reading that a new Mac has none enrolled. **It does have them:** the enrolled keys are listed in the signed registry (ADR-148 §P2-4), which a backup carries and `restore_bundle` puts back (only `keys/root.wrap.se` is left out), so a vault restored or copied onto a new Mac lists the lost Mac's keys, whose private halves are in that Mac's Secure Enclave. Requiring a proof there would make a recovery through the broker impossible for exactly the owner who forgot the passphrase and lost the Mac (and nothing in the broker can remove a presence key without a proof from one, `presence.unenrol`). So the review's request is **not adopted here; it is left to the owner** (`recovery.SECURITY-REVIEW.md`, P1-2). A presence challenge also needs a login session today (`presence.challenge` is `owner_session`), which a locked-out caller does not have, so adopting it needs a pre-login challenge as well. A Touch ID unlock wrap is re-sealed silently by the rotation, which needs the Secure Enclave helper; on a Mac without it while Touch ID unlock is on, the recovery refuses with nothing changed (ADR-148 §P1-1's rule), and the owner runs it on the Mac that holds the key or reads values offline.
7. **Never an agent, never MCP; a person at their own Mac.** The op needs no login (the caller is locked out by definition) and so, like the Touch ID unlock, refuses a caller the broker identifies as an agent — an agent token, or no token from inside a registered project folder — before any code is read (`capability_not_held`). On a broker that has not loaded the vault yet the registry is empty and no project folder can be recognised then, so `recover_with_code` asks again once the code has loaded the vault, before the second factor and before anything is rotated (review P1-1, 2026-11-14). It is on `credmgr_mcp::tools::FORBIDDEN_OPS` (I-13). The server runs it alone (an exclusive request barrier, as for any rotation) whenever the uid is not backed off — not only when the vault looks locked at the server's check, which an auto-lock before the dispatch could make stale (review P2-b); on an open vault it then refuses at once.
8. **Every attempt is audited, with no secret.** A success writes the rotation's own record (`system:vault.recover` / `vault.recovered_with_code`, counts only) and the dispatcher's decision record. A refusal while the vault is locked has no root key to sign a record with, so it waits in memory (time, actor, error tag; at most 64, the rest counted) and the next request that writes a record writes it first, at the time it was made (`server.rs::flush_unaudited_recoveries`). Neither the code nor either passphrase is ever echoed, logged or audited. `parse_recovery_code` now wipes its cleaned copy of the input and refuses a non-ASCII input instead of slicing inside a character (a panic the broker's panic guard caught, found while writing this).
9. **A vault without a recovery wrap** (one whose file was removed; every vault made by `vault.init_*` has one) answers `not_found` and changes nothing. `vault.status` carries `recoveryUnlock` (a public fact, the wrap file exists), so the Lock screen offers "Forgot passphrase? Use recovery code" only when it can work and otherwise says that the way in by code appears after the next passphrase change; `credmgr recover` says the same before reading anything. The next `vault.set_passphrase` or `maintenance.rotate_root` writes the wrap.
10. **Surfaces.** CLI `credmgr recover [--json]`: the code, the new passphrase (asked twice at a terminal) and any second-factor code from stdin or a prompt, never argv, held in `Zeroizing` buffers and wiped from the request after the call. App: on the Lock screen, "Forgot passphrase? Use recovery code" opens a form (code, new passphrase twice, second-factor code when the broker asks), then shows the new recovery code once and asks the owner to confirm it is saved before the vault opens. An open vault answers `malformed_request` (change the passphrase from Settings instead).

**Alternatives rejected.** `vault.unlock {method: "recovery"}` that just unlocks (leaves the vault open under a code that stays valid: a found code becomes a permanent second passphrase); a recovery that re-wraps the same root key under the new passphrase without rotating (a copied old `root.wrap.pass` or `root.wrap.recovery` would still open it); Argon2id over the code (item 3); a separate back-off counter (item 5); skipping the second factor (item 6); requiring Touch ID (item 6); writing refused attempts to an unsigned side log (a same-user attacker edits it; the signed trail is the one record, at the cost that a restart before the next unlock loses the in-memory list — stated in the review).

**Not done.** The app's recovery screen is tested against the fixture broker and in the shell's tests, **not pressed in a built app** (needs the operator's Mac; `RELEASE_VERIFICATION.md` rows marked not pressed). ADR-144's machine lock itself stays `2.1` work; this op is its prerequisite.

**Tests.** `crates/brokerd/tests/recover_unlock.rs` (17: success opens, forces the new passphrase and a new code, the used code and old passphrase dead on the running broker and after a restart; wrong, malformed, non-ASCII codes and bad params refused with the wraps byte-identical; an open vault; an agent token and an agent in a registered folder through the server, on a loaded broker and on a freshly started one whose registry is empty until the code loads it (review P1-1); a recovery whose node keys do not open answers locked with the new code and no login (review P2-a); a recovery request waits for the requests in flight even on a vault that looks open (review P2-b); a vault without a wrap until a passphrase change writes one; the second factor asked, a wrong one refused, a gate backup code accepted and spent across a restart, a presence key not asked; the shared back-off both ways round and a lockout that refuses even the right code; a crash before the commit and at every staging point keeps the old passphrase and the old code; a crash right after the commit and at every roll-forward point gives the new passphrase and kills the used code; an unproven commit answers the code and stays locked; a put-back wrap and a rolled-back vault folder open nothing; every attempt audited, those made while locked at the next unlock, and no file holds a secret; the waiting list is bounded); `crates/core/src/recovery.rs::parse_rejects_non_ascii_without_panicking`; `crates/mcp/tests/i13_tool_registry.rs::the_recovery_code_unlock_is_on_the_forbidden_list_and_no_tool_maps_to_it`; `crates/cli/tests/quick_cmds_cli.rs::recover_opens_the_vault_with_the_code_sets_the_new_passphrase_and_retires_the_code`; `crates/cli/tests/no_secret_in_argv.rs::recover_reads_the_code_and_the_new_passphrase_from_stdin`; the existing `rotate_root.rs` and `set_passphrase.rs` suites over the refactored rotation. App: `apps/desktop/tests/unit/recover-unlock.test.ts` (9: offered only with a wrap and otherwise says when it appears; the form's checks; a recovery against the fixture broker opens the vault, shows the new code once behind a tick, and the used code and old passphrase stop working; the second factor asked with the code and new passphrase kept typed, a wrong one refused; a pending rotation stays locked; back and lock wipe the form; the back-off; the error table's words), `src-tauri/tests/bridge_ops.rs::recover_sends_its_own_params_keeps_the_login_token_and_hands_back_the_new_code` and the whole-surface token sweep, `src-tauri/tests/bridge_wire.rs::recover_logs_in_only_when_the_broker_says_the_vault_is_open`, the drift guards (92 ops), and `tests/real/drift-guard.test.mjs` for the real-daemon shim.

**Amendment (ADR-165 N5, 2026-11-20).** The recovery's rotation now also gives every live node a new keypair and re-seals what it holds, in the same stage and under the same commit record (item 4's crash safety unchanged: old state or new, never neither), so a copy of the folder from before the recovery plus the used code or the forgotten passphrase opens nothing written after it. A locked node or a full tray does not refuse it. The answer gains `nodesRekeyed` and `filesResealed`. See ADR-165's fourth addendum.

**Amendment (wiring audit Q-2, 2026-11-21).** Item 7's rule now binds the other token-less last door too: `vault.gate_recover` (ADR-064) refuses an agent token or a call from inside a registered project folder before either factor is read, and asks again once a freshly started broker has loaded the registry, exactly as this op does. See ADR-064's amendment of the same date.

## ADR-164 · Node-scoped agent tokens: `agent.token_issue|status|rotate|revoke`, owner-only, one node, a short life, the secret shown once (2026-11-14)

**Context.** Quick win 18 and `18_ENDPOINT_INDEX` rows 168–171 planned four `agent.*` ops so an agent can hold a credential of its own instead of relying on its working folder (ADR-142) or, worse, on an exported owner login (K-6, `PHASE8_AUDIT_REPORT §4`). K-6's resolution is still the operator's open decision (a cwd-bound or single-command owner token for the CLI, or owner reach kept to the desktop bridge). The brief for this work says: follow K-6's decision, and where it is undecided take the most restrictive option and say so. Every choice below marked **(K-6, needs the owner's confirmation)** is that most restrictive reading.

**Decision.**

1. **The token.** A bearer `cma_` + 64 hex (256 bits from the OS RNG) and a public id `a_` + 16 hex drawn separately, so the id says nothing about the secret. The broker keeps only `SHA-256("credmgr-agent-token-v1\0" ‖ bearer)`; a presented bearer is hashed and compared with **every** live record in constant time, with no early exit. The record holds the node, the capabilities, a label (1–64 characters, no control characters), created, expires, last used and rotated times. `Debug` never prints the hash.
2. **Bound to one node, strictly.** A token's scope is `Origin::Agent` on exactly its node. It reaches **nothing else**: not global (R3), not ancestors (R4), not descendants, siblings or grants. Any other node is an R8 deny whose remedy says to issue a token for that node. `entry.search`, `entry.list` and every other cross-node read are filtered by the same rule (`ops::token_confined_away`, checked first in `resolve_capability`, `resolve_entry_capability` and `would_be_allowed_ignoring_lock`).
3. **Capabilities are a subset, twice.** At issue: a non-empty subset of `list, read, reveal, create, update` (`notes` and `admin` are never an agent's), and of what the node's `agentAccess` gives agents now; anything more is `malformed` naming the capability. At every request: the stored set is intersected again with the node's current ceiling (`scope::agent_token_ceiling`), so narrowing a node narrows its tokens at once and widening it never widens them. ADR-140's security levels apply unchanged: a token is `Origin::Agent`, so Guarded holds high and critical reveals as approvals and Sealed holds every reveal.
4. **A short, mandatory life.** `expiresIn` defaults to 24 h, is at most 7 days and at least 60 s; there is no "never". An expired token is refused on its next request. At most 32 live tokens.
5. **Revocation is effective on the next request.** `agent.token_revoke` removes the record; the next request that presents the bearer gets `session_expired` (ADR-068's answer for a presented token that names no scope), never a fall-back to the cwd or global scope. Up to 256 tombstones (revoked, rotated, expired) are kept by hash so the refusal is audited as `Agent:a_…(revoked|rotated|expired)`.
6. **Memory only.** Tokens live in the broker's memory; a restart revokes every one, and nothing is written to disk. A vault lock does not end them (R1 still blocks reveal and update while locked, exactly as for a cwd agent).
7. **Only the owner's login reaches any of the four ops.** Each refuses an agent first (`capability_not_held`) and then requires a live login (ADR-065). **An agent can never mint, widen, narrow, rotate, list or revoke a token, its own included**, and no MCP tool reaches the ops (`FORBIDDEN_OPS`; I-13 also forbids `token` in a tool name).
8. **Issuing and rotating create a secret, so they take `grant.create`'s gate:** a fresh second factor where a gate is enrolled, then a Touch ID proof for exactly that request (ADR-098; `presence_reason` names both). Every check that needs no finger runs first. **There is no passphrase fallback: with no presence key enrolled, issuing is unreachable**, as `grant.create` is. **(K-6, needs the owner's confirmation.)** Revoking only removes access and waits on neither, like `grant.revoke`.
9. **The secret is shown once.** Only the issue and rotate answers carry `token` (with `shownOnce: true`). `agent.token_status` returns metadata — id, label, node, capabilities, effective capabilities, the four times — and the planned `{hasToken, last4}` shape is replaced because no part of the secret is stored. The audit record of an issue holds the op and node, never the answer; `redact_bearer_tokens` scrubs `cma_` as it scrubs `cmt_`.
10. **Every request is audited under the token's public id** (`Agent:a_…`, ADR-077).
11. **MCP presents only an agent token.** `credmgr mcp` reads `CREDMGR_AGENT_TOKEN` and only a well-formed `cma_` value; it never reads `CREDMGR_TOKEN`, and refuses to start on a malformed value or a login (`cmt_`), without echoing it. An owner login exported into an agent's shell therefore never reaches the MCP server. **(K-6, needs the owner's confirmation.)** The command line presents `CREDMGR_TOKEN`, which may hold an agent token.
12. **CLI.** `credmgr agent token issue <node> --label … --cap … [--expires 90m|8h|2d|secs]`, `ls|list|status [--node]`, `rotate <id> [--expires]`, `revoke <id>`, all with `--json`. Subcommands of ADR-142's `agent`, so the top-level count does not change. The bearer goes alone to stdout, the details to stderr.
13. **Desktop: the token never reaches the webview.** The agents screen gets an "Agent tokens" section: the list with expiry and Revoke, and an issue dialog. ADR-057's rule for the login (no bearer ever reaches the page; `tests/bridge_ops.rs` sweeps every bridged result for a `"token"` field) applies to this bearer too, so `agent_token_issue` and `agent_token_rotate` are hand-written shell commands, not table rows: the shell takes a clipboard ticket before the call, takes `token` (and `shownOnce`) off the answer, writes the token to the concealed, self-clearing clipboard as `entry_copy` writes a value (cleared after 30 seconds and at lock, refused if a lock came between), wipes its own copy, and answers the metadata with `copied: true, clearAfterSeconds`. If the clipboard cannot take it, nobody holds the token, so the shell revokes it at once and answers `copied: false, revoked`. The dialog says the token is on the clipboard and is shown nowhere; there is no Copy button, because there is nothing left to copy. The CLI still prints the token once on stdout (a terminal is not a webview).

**Counts.** Broker ops 91 → 95; bridged commands 91 → 95 (`HAND_WRITTEN` 8 → 10, the two that carry a bearer; `TABLE` 83 → 85); shell commands 17 (unchanged); MCP tools 21 (unchanged); error codes 27 (unchanged — `session_expired`, `capability_not_held`, `presence_required`, `second_factor_required`, `not_found` and `malformed` are reused); CLI top-level commands 45 (unchanged). None of the four is in `PERSISTED_OPS` (nothing is written to disk).

**Alternatives rejected.** Storing tokens on disk (survives restart, but a stolen vault copy then carries live bearers, and K-7 already prefers memory-only bookkeeping); letting a token reach its node's descendants or grants as a login does (one token for many projects is K-6 again in miniature); minting by an agent within its own scope (any minting by an agent is a way to extend a life or hand on access — the brief forbids it); a "never expires" option; a passphrase fallback without Touch ID (the passphrase may be typed in a shell an agent watches); keeping last4 for the list (a fragment of the secret in every listing for no gain the id does not give); an MCP tool to issue (the confused-deputy route).

**Amended (ADR-174, 2026-11-20): K-6 is closed.** The owner decided that an exported login works only from its own project folder. A login handed to a token-less caller inside a registered project folder is a project login (`Origin::Cli`, that node only, `list`/`read`/`reveal`/`create`/`update`, the folder recorded), honoured only from a process whose working directory is inside one of that project's registered folders (otherwise `session_expired` and `anomaly.project_login_wrong_folder`); the owner's login from outside every project folder is unchanged. Test: `crates/brokerd/tests/adr174_k6.rs` (4). The agent token of this ADR stays the way to give an agent a credential of its own.

**Not done, and why.** Rate limiting unknown bearers (256-bit entropy makes guessing infeasible; noted in the security review). Durable tokens across restarts (above). The desktop section is tested against the fixture broker only, **not pressed in a built app** (`RELEASE_VERIFICATION.md` rows marked "not pressed — new in ADR-164"). K-6 itself (an exported owner login on the command line) is not resolved here; this ADR gives agents a narrower credential and keeps MCP away from the login.

**Tests.** `crates/brokerd/src/token.rs` (5 unit: shape, hashing, constant-time lookup, rotation, tombstones); `crates/brokerd/tests/agent_tokens.rs` (6: the gate order, no prompt for a request that will be refused, the secret never listed, logged or audited, an agent cannot mint/widen/rotate/list/revoke, rotation/revocation/expiry, restart and narrowing); `crates/brokerd/tests/isolation.rs` I-30a–d (own node only, no owner op, refused after revoke and expiry and audited by name, Sealed (shown as "Strict", ADR-152) and Guarded and the ceiling still bind); `crates/mcp` (`only_an_agent_token_is_ever_presented`, I-13 `no_tool_reaches_the_agent_token_ops`); `crates/cli/src/agent_tokens.rs` (2 unit); `apps/desktop/src-tauri/tests/bridge_ops.rs` (the token sweep now covers the four commands and also refuses `cma_`; `an_agent_token_goes_to_the_concealed_clipboard_never_to_the_webview`; `an_agent_token_that_cannot_be_copied_is_revoked_not_shown`); desktop unit tests in `apps/desktop/tests/unit/agent-tokens.test.ts`. The sweep had a latent gap that this work found and closed: seventeen ops (ADR-098/148 presence, ADR-131–135) had no `realistic()` shape, so the fake broker's thread died at `presence.status` and every later entry met a dead socket and passed vacuously; they now have shapes, and the sweep refuses `broker_unreachable`.

**Addendum (2026-11-14): the independent review's findings.** An independent review of the first commit found two P1 and twelve P2 issues. What changed:

- **A sealed node's tokens end with it (P1-1).** `node.seal` revokes every agent token of the node it seals, on both the durable and the in-memory path (`TokenStore::revoke_agents_for_node`), and `resolve_scope_at` treats a live token whose node is not in the registry as dead (`kill_agent`, tombstone reason `node_gone`). So `node.restore` within the seven days, or a new node under the same id, never revives a token. Tests: `agent_tokens.rs` `a_sealed_nodes_tokens_end_with_it_and_a_restore_does_not_revive_them` and `a_token_whose_node_left_the_registry_is_dead_even_when_the_id_comes_back`; isolation I-30e.
- **The owner sees which token asked (P1-2).** A reveal approval (`PendingApproval.agent_token`) and a switchboard setting request (`SettingRequest.agent_token`) record the token's public id and label, and are keyed by the public id, so one token's request is never merged with another's and a rotation keeps the same request. `approval.list|get` and `settings.request_list|get` show `agentToken {id, label}` to the owner only. The CLI's `approvals` and `settings requests` say "asked by agent token “label” (a_…)"; the desktop's settings-request rows say the same, and its approval picker does whenever the answer names the token.
- **The Touch ID sentence names what is signed (P2-1):** "Issue a 7-day agent token for project acme that may list, read: “ci”" (rotate: "Give agent token “ci” (project acme, may list, read) a new secret for 1 day"); label cut to 40 characters, sentence to 240.
- **The audit trail names the token (P2-2):** an issue, rotate or revoke record carries `token a_…; node …; caps …; expires …`, and a refused one names the id it was asked about.
- **Global is refused (P2-7).** A token for Global would see every shared secret and, through `audit.tail`, the owner's whole action stream. `agent.token_issue` refuses Global with `malformed` (issue it for the project the agent works on); the CLI and the dialog do not offer it. **(K-6, needs the owner's confirmation:** the alternative is an explicit `--global` with a warning.)
- **Expiry also runs on a monotonic clock (P2-8):** each token keeps an `Instant` deadline alongside `expiresAt` and is refused when either has passed, so setting the clock back does not extend a life.
- **The bearer is wiped after use (P2-5):** issue and rotate hand it out in `Zeroizing<String>`, `BrokerScope` zeroizes its bearer on drop, and the server wipes the response body and wire buffer once written. The kernel's socket buffers and the `BufWriter` copy are outside the broker's reach (K-10); the design note now says "the store never keeps it in the clear".
- **MCP refuses a malformed token on every call (P2-9),** not only at the CLI's start: `transport::call` answers `TransportError::Config` without echoing the value, so no embedder falls back to the cwd scope.
- **Anomaly for a token used from another project's folder (P2-10):** `anomaly.agent_token_workdir_mismatch`, naming the token's public id; the request still proceeds. Isolation I-30f.
- **Desktop: a lock mid-issue (P2-4).** A real lock ends the login a revoke needs, so the shell's immediate revoke is refused (`session_expired`). The shell now keeps the public id (never the bearer) on its session and revokes it right after the next unlock; the answer says `copied: false, revoked: false, revokePending: true` and the dialog says the token will be revoked when the vault is unlocked. An answer that names a token but carries no usable text token is revoked too. The test's fake broker now refuses the revoke after the simulated lock, as the real one does, and checks the revoke at the next unlock.
- **The desktop's "page never holds the token" test can fail now (P2-6):** a case where the fixture's answer carries a token-shaped value checks that neither state nor render keeps it (checked by mutation).
- **Naming (P2-12):** the level is Sealed in code, shown as "Strict" (ADR-152); the test comment and this ADR say so.

**Re-review of the fixes (N-1 to N-4).**

- **N-1:** the seal tests no longer present the token between the seal and the restore, so they fail if the seal-time revoke is removed. Before, the missing-node check in scope resolution would have ended the token anyway.
- **N-2:** `vault.approval_get` lists approvals pending on every node. It is now refused to every identified agent (an agent token, or a folder registered to a node), locked or not. Before, on a locked vault, any agent could read it, including the requesting tokens' ids and labels. `agentToken` is shown to the owner only, like the folder. The token-less Lock screen still reads the list while locked (ADR-088). The broker cannot tell it from a process in an unregistered folder, which already sees what the Lock screen sees, but never a token's id or label. Test: `no_agent_reads_the_pending_approvals_of_other_nodes_even_while_the_vault_is_locked`.
- **N-3:** a label with a control character, a Unicode format character (bidi embeddings, overrides and isolates, zero-width characters, the BOM, tag characters and the like), a line or paragraph separator, or an invisible filler is refused at issue. Rotation takes no label. The Touch ID sentence drops the same characters. Test: `a_label_with_direction_changing_or_invisible_characters_is_refused`.
- **N-4:** the wrong-folder anomaly is filed under the token's node, so its detail no longer names the other node or the folder ("presented from a folder registered to another project").

**Left as they are.** **P2-3, tokens survive `vault.lock`:** decision 6 stands; it is the owner's design decision (R1 still blocks reveal and update while locked). **P2-11, up to 30 seconds on the general pasteboard:** concealed and self-clearing as `entry_copy`; a CLI write-to-file path or a shorter clipboard life is a possible follow-up, not built.

## ADR-165 · Machine lock: the passphrase wrap sealed to a device key file on this Mac (the smallest safe version of ADR-144) (2026-11-14)

**Context.** ADR-144 defined the smallest honest machine lock and did not build it, because it changes how the root key is opened and needed a recovery-code unlock first, so that a lost device key could never lock an owner out. ADR-163 built that unlock (`vault.recover`). This builds the lock itself, file tier only, and moves the three `keystore.*` rows from `planned` to `built`. The Windows and Linux keystores stay `2.1` work (ADR-147).

**Decision.**

1. **A device key, file tier only.** `<state>/machine/lock.key`: 32 bytes from the OS CSPRNG, mode 0600, in a 0700 directory, outside the vault folder (bind refuses a state directory that resolves inside it). It is made once: written to a temporary file with `create_new`, fsynced, then hard-linked into place, so it never replaces an existing key, and an existing key that cannot be read is never overwritten. Unbind keeps it, so binding again reuses it. **No Secure Enclave seal in this version**, and the words say so everywhere: it protects a *copied vault folder* (a synced or shared folder, a copied directory; *the addendum below corrects this list: not CredMgr backups, Time Machine or whole-disk images*), not a stolen or unlocked Mac, whose disk holds both the key and the sealed wrap (FileVault is the answer to that, `05 §4`).
2. **The seal is the file.** A bound `keys/root.wrap.pass` is `CMMLOCK1 ‖ key id (8) ‖ nonce (12) ‖ ChaCha20-Poly1305(device key, plain wrap)` with `CMMLOCK1 ‖ key id` as associated data (120 bytes); the key id is the first 8 bytes of `SHA-256("credmgr/v2/machine-lock/key-id\0" ‖ key)`. "Bound" is that form of the file, never a flag, so the two cannot disagree. A file that does not start with the magic, or is exactly the 76 bytes of a plain Argon2id wrap (a plain wrap whose random salt happens to start with the magic), is plain and is opened **exactly as before**, byte for byte (`crates/keystore/src/machine_lock.rs::classify`).
3. **Opening.** The in-memory wrap stays the raw file bytes; every passphrase check (`root_from_passphrase`: unlock, `session.confirm`, approvals, `vault.gate_recover`, rotation, passphrase change) unseals first through `plain_pass_wrap`. A missing key, a different key, an unreadable key file or a damaged sealed file is the new wire error **`machine_lock_refused`** with `reason` (`device_key_missing`, `device_key_mismatch`, `device_key_unreadable`, `sealed_wrap_damaged`, `device_key_unwritable`), a message and a `remedy` naming the recovery code (`credmgr recover`, the Lock screen's "Forgot passphrase?"). The passphrase was never tried, so it is not `wrong_passphrase` and does not count in the guessing back-off (27 → 28 error codes).
4. **The recovery code never needs the key.** `root.wrap.recovery` is never sealed, so `vault.recover` (and `scripts/emergency-decrypt.mjs`) open a bound vault on any computer. The rotation `vault.recover` runs writes the new passphrase wrap sealed to *this* Mac's device key (made if missing), so recovering on a new Mac moves the lock to it rather than dropping it; the answer says `machineLocked` and `deviceKeyCreated`. Only if the key can neither be read nor made does the rotation write the wrap plain and say `machineLockRemoved`, because a sealed wrap no key can open would be a lockout. A root rotation and a passphrase change re-seal under the same key (`rotation_response.machineLocked`).
5. **Ops.** `keystore.status` (the honest state: `bound`, `tier` `"file"`/`"off"`, `secureEnclave: false`, `opensHere`, key ids, `damaged`, `recoveryUnlock`, and `protects` / `doesNotProtect` sentences), `keystore.bind` (the vault open, `admin`, the owner's login, a recovery code set up — `root.wrap.recovery` present and well formed — and idempotent) and `keystore.unbind` (the same, plus a fresh second factor when one is enrolled and a presence proof every time once a presence key is enrolled, `PRESENCE_EVERY_TIME`). All three refuse an agent token, or a token-less call from inside a registered project folder, before anything is read (`capability_not_held`), and are on `credmgr_mcp::tools::FORBIDDEN_OPS` (I-13): an agent may neither weaken the lock nor learn whether a vault is tied to this Mac. 92 → 95 broker ops, still 21 MCP tools.
6. **Writes are atomic and checked.** Bind and unbind take the exclusive request barrier and the vault lock rotation uses, seal, check that the sealed form opens back to the same plain wrap, write `root.wrap.pass` with one atomic replace, read it back, and put the old bytes back if the read differs. The device key is durable before any wrap that needs it is written. A crash at any point leaves a wrap the passphrase opens on this Mac (tested at both fault points for both directions).
7. **Backup and restore.** *(Superseded by the addendum below, P0-2 and P1-3: a CredMgr backup now carries the wrap unsealed inside its own encryption, and Time Machine does carry the device key.)* A backup copies the vault files as they are, so the sealed wrap stays sealed; the device key is in the state directory and is never in a backup. Restored on the same Mac it opens with the passphrase; on a new Mac the passphrase is refused with `device_key_missing` and the recovery code opens it and seals it to the new Mac; an old Mac's key copied over is a mismatch.
8. **Surfaces.** CLI `credmgr keystore status|bind|unbind [--json]` (47 commands): `status` prints "machine lock: on (device key file on this Mac; not sealed in the Secure Enclave)" or "off", what it protects and what it does not; `bind` names `credmgr recover` as the way in on another Mac. App: Settings > Security > Machine lock, a status line and chip read from `keystore.status` and a Bind…/Unbind… button that opens a dialog first; the bind dialog says that if this Mac is replaced the passphrase will not open the vault there and the recovery code will, and that a stolen or unlocked Mac is not protected. Bridged as three generated commands (9 + 86 = 95). The Lock screen routes `machine_lock_refused` to "Forgot passphrase? Use recovery code", never to "Wrong passphrase".

**Alternatives rejected.** A daemon-side flag or check (a speed bump: anyone with the folder runs their own daemon, ADR-144); sealing the recovery wrap too (a lost key would then be a permanent lockout); deleting the device key on unbind (a crash between the unbind write and the delete is harmless, but a stale sealed copy in a backup would then be unopenable by the passphrase anywhere; keeping the key costs nothing); dropping the lock on a recovery instead of re-sealing (the owner who recovers on a new Mac would silently lose the protection they chose); a Secure Enclave tier now (the right next step on a Mac with the chip, but it needs the presence helper on every unlock path and its own review).

**Not done.** The Secure Enclave tier; the Windows and Linux keystores (`2.1`, ADR-147). `keystore.status` needs the owner's login, so a locked vault cannot be asked whether it is bound (the Lock screen learns it from the refusal). Bind checks that the recovery wrap exists and parses, not that the owner still holds the code (it cannot know). The app's row and dialog are tested against the fixture broker and in the shell's drift tests, **not pressed in a built app** (`RELEASE_VERIFICATION.md` rows marked not pressed). The desktop shell was compiled and its tests run (all green but `tests/real_broker.rs`, which needs a built `credmgrd` that disk space did not allow at that point; its four tests exercise field operations this change does not touch).

**Tests.** `crates/keystore/src/machine_lock.rs` (4: seal and open; a plain wrap whose salt starts with the magic stays plain; another key, a flipped byte, a swapped key id and truncation refused; the key made once with mode 0600 and never replaced). `crates/brokerd/tests/machine_lock.rs` (14: an unbound vault opens exactly as before; bind seals, the key is 0600 outside the vault and in no vault file, status honest, idempotent; a copied folder without the key is refused with the pointer to the recovery code, even with a wrong passphrase, and the code opens it; a refusal never feeds the back-off; a wrong or short key file refused and never replaced; a truncated, flipped or relabelled wrap refused and the code reseals; a crash after the key and before the rename, for bind and unbind; bind with no or a damaged recovery wrap refused; a key inside the vault folder refused; unbind needs the second factor, then presence, and keeps the key; an agent token and a token-less project-folder caller refused for all three ops with nothing read or changed; rotation and passphrase change while bound reseal to the same key, and a key lost mid-session refuses the rotation; a backup keeps the wrap sealed and holds no key, restores on the same Mac, on a new Mac opens only through the recovery code and is locked to the new Mac, and an old key is a mismatch; a lost key on the same Mac recovered and rebound). `crates/mcp/tests/i13_tool_registry.rs::the_machine_lock_ops_are_on_the_forbidden_list_and_no_tool_maps_to_them`; `crates/cli/tests/quick_cmds_cli.rs::keystore_status_bind_and_unbind_round_trip_and_the_vault_still_opens`. App: `apps/desktop/tests/unit/machine-lock.test.ts` (9: the honest row; the dialog asks first and its words name the replaced Mac and the recovery code; bind's exact command; no Bind without a recovery code; unbind needs Touch ID, then works and keeps the key; the second factor; the error table), the fixture broker's `keystore_*` examples in `fixture-shape.test.ts`, `src-tauri/tests/bridge_ops.rs` sweeps, the drift guards (95 ops) and `tests/real/drift-guard.test.mjs`. `scripts/endpoint-matrix.py` against the real daemon: status off, an agent refused for each op, bind (a new key, then idempotent), status bound and opening here, unbind (the key kept, then idempotent) — 95 of 95 ops, 351 rows; the same change adds the two `vault.recover` refusal rows ADR-163 left out, without which the matrix would not start.

### ADR-165 addendum · what the independent review changed (2026-11-14)

An independent review of the first build found 2 P0, 4 P1 and 8 P2. Each was checked against the code; all fourteen were real. The rule the fixes follow: **an owner who has their passphrase or their current recovery code is never locked out, and a copied folder plus the passphrase never opens what a bound vault wrote after the bind.** Where the two pull apart, the first wins, and the gap is written down here and shown on the screens.

1. **P0-1, bind is now a root rotation that re-keys every project.** Sealing the existing wrap was not enough: every older plain `root.wrap.pass` (a synced folder's history, a snapshot, a copy) still wrapped the same root key, so putting one back undid the lock. Rotating the root alone would not have been enough either, and this was checked in the code: `rotate_root_locked` re-wraps node private keys, it does not replace them, and entries are sealed to a node's X25519 public key. A whole pre-bind copy (old wrap **and** old node-key wraps) plus the passphrase gives the old root key, then the old node private keys, which open envelopes written after the bind. So `keystore.bind` now (a) proves the passphrase and the current recovery code, (b) refuses with nothing changed while a project is locked, something waits in the tray or the sealed entries hold anything (every key is replaced, and those cannot be re-sealed safely in the same step), (c) makes the device key, (d) writes a **bind record** at `<state>/machine/vaults/<sha256(vault path)>.json` with the pre-bind node public keys, (e) runs a root rotation that must seal its new wrap (a new recovery code is issued; the old one stops working) and gives the sealed-entries node a new cold key pair in the same commit, and (f) re-keys every live node, global included, with `node.rekey`'s protocol. The answer lists `nodesRekeyed`, any `rekeyFailed`, `orphanKeyReplaced`, the `rotation` and the new `recoveryCode`. **What a pre-bind copy already held stays readable in it with the passphrase**: nothing can take that back, and the bind dialog, `credmgr keystore bind` and `keystore.status` say so. Status now notices the swap: `plainWhileBound` (the record exists, the file is plain) with a `warning`, and `preBindNodes` (live nodes still on a key from the record, after an interrupted bind or a sealed project restored later); binding again finishes the job. A swapped-in old plain wrap that the passphrase opens but whose root no longer opens the vault is `machine_lock_refused` with the new reason **`plain_wrap_while_bound`** (the passphrase was right, so it does not count as a guess), and the recovery code opens and re-seals. A rotation re-seals whenever the record exists, so a swapped plain file cannot silently unbind the live vault.
2. **P0-2, an old backup + a lost device key + a later rotation was a lockout. Chosen fix: a CredMgr backup carries the passphrase file unsealed inside its own encryption.** The archive is already encrypted under the backup passphrase; it now stores the plain Argon2id wrap instead of the sealed bytes, so an old backup always opens with the vault passphrase of its day (and with that day's recovery code), whatever happened to the device key since. To keep the archive from being an easy way round the lock, `maintenance.backup` on a bound vault requires the owner's login and refuses a backup passphrase that opens the vault's passphrase wrap (`backups/` sits inside the vault folder, so a copy of the folder carries the archives). Disclosed as **"the lock covers copies of the vault folder, not CredMgr backups"**: backup passphrase + vault passphrase opens a backup anywhere. Rejected: putting the device key in the backup (backup + passphrase would open everything, silently); a recovery wrap kept valid for older backups (a second long-lived secret whose rotation story is worse than the problem). **Owner question O-1.**
3. **P1-1, bind proves the recovery code.** `keystore.bind` takes `passphrase` and `recoveryCode`; the code must open the current recovery wrap to the root key in memory, the passphrase must open the passphrase wrap. A wrong one is `recovery_code_mismatch` / `wrong_passphrase` and both count in the per-uid back-off (`keystore.bind` is an auth path in `server.rs`). CLI: `credmgr keystore bind` prompts for both on stdin. App: two masked fields in the bind dialog, held outside page state and wiped on close or lock.
4. **P1-2, temporary files.** `store::atomic::write` removes its temporary file when the rename fails; `write_temp` is the seam the crash test now uses for real. A temporary file a crash leaves next to `root.wrap.pass` is swept under the vault lock by the next bind, unbind or unlock (`remove_stray_temps`, which touches only that target's `.<name>.tmp.*` files). A failure to fsync **after** the rename is reported as what it is: `internal`, "the passphrase file WAS changed: the vault is now bound / not bound ...", and the in-memory wrap is set to what is on disk.
5. **P1-3, the device key is in Time Machine; the claims were wrong. Decision: do NOT exclude it.** The key lives in `~/Library/Application Support`, which Time Machine, whole-disk images and Migration Assistant copy. Excluding it (the `com.apple.metadata:com_apple_backup_excludeItem` attribute) would make every snapshot of a bound vault older than the last rotation unopenable with the passphrase and the current code once the Mac is lost: exactly the lockout the overriding rule forbids. So the key stays in Time Machine, and every sentence that said "never in a backup" now says that Time Machine, whole-disk images and Migration Assistant carry the key with the folder, and that the lock does not cover them (`keystore.status`'s `doesNotProtect`, the dialog, the CLI, `05 §4`). Status reports `deviceKeyModeOpen` and `deviceKeyForeignOwner`. **Owner question O-2.**
6. **P1-4, a dropped lock is shown.** `vault.recover`, `vault.set_passphrase` and `maintenance.rotate_root` already answered `machineLockRemoved`; now `credmgr recover` and `credmgr passphrase` print "warning: the machine lock is OFF now ...", the Lock screen's recovery step shows it before the app opens, and the passphrase change and rotation show a warning notice. Status keeps saying it (`plainWhileBound`).
7. **P2s.** P2-1: the device key's temporary name is unique (`lock.key.tmp.<pid>.<random>`, `create_new`, `O_NOFOLLOW`); the key on disk always wins and is what is returned. P2-2: the rotation's re-seal applies bind's "key inside the vault folder" guard and writes the wrap plain with `machineLockRemoved` rather than put the key into the folder. P2-3: the key is opened with `O_NOFOLLOW | O_NONBLOCK`, must be a regular file, is read to at most 33 bytes, and an open mode is narrowed to 0600; the directory is made 0700 and a symlink or non-directory is refused. P2-4: with no presence key and no confirmed gate, `keystore.unbind` needs `passphrase` (counted in the back-off). P2-5: a 76-byte file that starts with the magic and does not open as a plain wrap is `sealed_wrap_damaged`, not `wrong_passphrase`. P2-6 (two Macs on one synced folder): not fixable cheaply — a bind on one Mac ties the folder to that Mac's key, and a recovery on the other moves it there and retires the code. Disclosed in the dialog and the CLI ("another Mac using this folder needs the recovery code"). **Owner question O-3.** P2-7 (the 8-byte key id links every copy to one device): left as is and disclosed; it reveals nothing about the key. **Owner question O-4.** P2-8: the crash test now runs the real temporary file at four fault points (after the device key, after the rotation, before the rename, after the rename), the agent test counts status reads, and the review's missing tests exist (below).

**Gaps that remain, said plainly.** A copy made before the bind keeps what it held. An old **folder copy** (not a CredMgr backup) made while bound, restored after a later rotation on a Mac without the key, needs the recovery code of its own day or the device key from Time Machine. After restoring an older backup, bind asks for that backup's recovery code; an owner who holds only the newest code opens the restored vault with the passphrase, rotates the root (a new code) and binds. Bind needs no presence proof or second factor even though it rotates and re-keys: the gates were left unchanged as the brief asked (**owner question O-5**). The app's controls are tested against the fixture broker, not pressed in a built app.

**Owner questions** (all five closed 2026-11-20 by ADR-174, see the seventh addendum below). O-1: is "CredMgr backups open with backup passphrase + vault passphrase, the lock does not cover them" acceptable, or should a bound vault's backup also be sealed (and the old-backup lockout accepted)? O-2: keep the device key in Time Machine (no lockout; Time Machine is not covered), or exclude it (Time Machine covered; old snapshots need that day's recovery code)? O-3: is disclosure enough for two Macs sharing one folder, or should bind refuse a folder another Mac has bound? O-4: is the stable key id acceptable? O-5: should bind need Touch ID / a fresh second factor, like a rotation?

**Tests added.** `crates/brokerd/tests/machine_lock.rs` (20, from 14): the swap attack replayed with a whole pre-bind copy and the passphrase against data written after the bind, and the file-swap variant (`plain_wrap_while_bound`, then the code re-seals); bind proves the current code and the passphrase and a wrong one is a counted guess; an old backup opens with the passphrase after a rotation and a lost key; a rotation never makes the key inside the vault folder and says the lock was removed; a recovery that cannot seal says so and status keeps saying it; unbind with nothing enrolled needs the passphrase; the crash test at four real fault points; the agent test counting status reads. `crates/keystore/src/machine_lock.rs` (7, from 4): racing creators, symlinks and an open mode, the truncated seal. `crates/store/src/atomic.rs` and `backup.rs`: a failed rename removes its temporary file; stray temporaries of one target only; the archived wrap replaced and nothing else. `apps/desktop/tests/unit/machine-lock.test.ts`, `src-tauri/tests/bridge_ops.rs` (the two commands' params) and `crates/cli/tests/quick_cmds_cli.rs` (bind with the code, the new code, `credmgr recover` printing the lock state).

### ADR-165 second addendum · what the re-review changed (2026-11-14)

A re-review of the fixes found 12 of the 14 findings fixed (P2-6 and P2-7 stay owner questions), no new P0, and 2 new P1 and 4 new P2 (N1–N6). The same rule decides each: no lockout for an owner with the passphrase or the current recovery code, and a copied folder plus the passphrase never opens what a bound vault wrote after the bind.

1. **N1, bind is two phases, so the owner provably holds the new code before anything commits.** `keystore.bind` takes a required `phase`. **`prepare`** (`passphrase`, current `recoveryCode`, both proven and both counted in the back-off as before) draws the new root key, makes its plain Argon2id passphrase wrap from the proven passphrase and draws the new recovery code, and keeps all three **in broker memory only** (`PendingBind`), tied to a digest of the root key the vault runs under now, for 600 seconds; it answers `newRecoveryCode` and writes nothing: no device key, no record, no wrap, no `vault.id`. **`commit`** takes the new code typed back, whole, and compares it in constant time with the drawn one; only then does it write `vault.id`, the device key and the bind record, run the rotation **with the prepared material** (so the code installed is exactly the one typed back) and re-key. **`cancel`** forgets it. A prepared bind is also dropped by a lock, a broker restart, any rotation (the root digest no longer matches) and its expiry; each leaves the old code and the old root key fully valid, because nothing durable was changed. A wrong retype is `recovery_code_mismatch` but is **not** counted in the back-off and keeps the prepared bind: the code was shown to this same login seconds earlier, so a retype guesses at nothing. A commit with none prepared, expired or overtaken is `malformed_request` "the machine lock was not turned on (nothing changed)". On a vault already bound here, prepare draws nothing (`already: true`, `newRecoveryCode: null`) and commit re-keys any node still on a pre-bind key. *Why the whole code typed back, not a part:* it matches `vault.init_confirm`, which already asks for the whole code; it proves the exact string the owner will need on a new Mac, including a mis-copied group a partial check would miss; and its cost (one paste or 39 characters) is paid once. CLI: `credmgr keystore bind` prompts for the passphrase and the current code, prints "Nothing has changed yet." and the new code once, and asks for it back up to three times; an empty line cancels, and three misses leave the vault as it was. App: the bind dialog's second step shows the new code and a retype field, and "Turn the lock on" commits; closing the dialog (or Escape, or a lock) cancels. The response to the commit never repeats the code. Crash and abandon tests at each phase: an abandoned prepare (a restart, a lock, expiry, cancel, a rotation in between) leaves every file byte for byte as it was and the old code working; a crash in the commit during staging or before the rotation commits leaves the old code working; the four fault points of the first addendum now fire inside the commit.
2. **N2, while bound, CredMgr backups are written outside the vault folder.** `maintenance.backup` on a vault that is sealed, or that this Mac's bind record names, writes to `<state>/backups/<vault id>/`, beside the device key, and answers `outsideVaultFolder: true`; an unbound vault keeps writing into `<vault>/backups/`. The state folder already holds the device key, which opens the sealed file, so an archive there gives a holder of that folder nothing new, while a copy of the vault folder no longer carries any post-bind archive. The doctor's registry rebuild looks in both folders. Rejected: a user-chosen location (one more setting whose default would be the same folder, and a wrong choice — a synced folder — reopens N2 silently); sealing in-folder archives to the device key and making them recoverable with the current recovery code (that is P0-2's lockout for an owner with only an older code after a rotation, and it makes every backup depend on the recovery wrap of its day). The status sentence, the dialog, the Backup panel caption, the About page, the CLI and `05 §4` now say where archives go while bound. **Disclosed:** archives written before the bind stay in `<vault>/backups/` and hold pre-bind data (the same as any pre-bind copy); an archive the owner copies elsewhere by hand is not covered. **Owner question O-6.**
3. **N3, the oracle is removed.** The check that refused a backup passphrase equal to the vault passphrase is gone (it answered "this is your vault passphrase" at Argon2id speed with no back-off). It is not needed once the archive is not in the vault folder. The owner's login is still required for a backup that carries the unsealed wrap.
4. **N4, the bind record follows the vault, not its path; an interrupted unbind never turns the lock back on.** A vault gets an identity, `<vault>/vault.id` (32 random lower-case hex digits), written by the first bind commit (or by a re-seal that finds no record). The record is `<state>/machine/vaults/<vault id>.json` and carries `vaultId`; a record whose id does not match is ignored. `vault.id` is in the backup's file list, so a restore of a post-bind archive keeps its identity; a different vault created or restored at the same path has its own identity (or none) and inherits nothing. Unbind now removes the record **before** writing the plain wrap: a crash between the two leaves a sealed file with no record, which still opens with the passphrase here, is still reported `bound`, and a later rotation keeps it sealed rather than turning on a lock the owner had turned off; unbinding again finishes. If the plain wrap is not written, the record is put back. *Known limit, disclosed:* anyone who can write to the vault folder can edit `vault.id` and detach the record; the effect is only that `plainWhileBound` is not reported after a swap, and the swap itself is still refused (the root was rotated at bind, so an old plain wrap opens nothing live). Status adds `markedBound`. Test `an_interrupted_unbind_never_turns_the_lock_back_on_and_the_record_follows_the_vault_not_its_path` (the new fault point `AfterRecordRemoved`, a post-rename fsync failure, and a different vault at the same path).
5. **N5, pre-existing, disclosed and not changed here.** `vault.recover` and `vault.set_passphrase` rotate the root key but re-wrap the node key pairs rather than replace them; only bind re-keys. So after a recovery or a passphrase change prompted by a leak, an old folder copy plus the old passphrase (and, if it was bound, the old Mac's device key) still yields the node private keys, which open entries written later in any later copy. **Follow-up:** re-key every live node in `vault.recover` and `vault.set_passphrase` as bind does, with the same refusals for locked nodes and the tray. Written in `05 §4` and the security review. **Closed 2026-11-20 by the fourth addendum below** (without the refusals: a locked node and the tray are re-keyed too).
6. **N6, a backup after the device key went away says what to do.** A bound vault whose key is missing, unreadable or different while the vault is open cannot unseal the wrap for the archive; `maintenance.backup` now answers `machine_lock_refused` with `reason` **`backup_needs_device_key`**, a message saying the backup was not written and a remedy: put the key file back (`<state>/machine/lock.key`, from Time Machine), or lock the vault and open it with the recovery code, which seals to a new key, then back up. Nothing is written. *Why not wrap a fresh plain wrap from the session root and the backup passphrase:* the archive's wrap must open with the **vault** passphrase of its day, which the broker does not hold; asking for it again here would be a passphrase check outside the back-off (N3 again). Test `a_backup_after_the_device_key_went_away_says_what_to_do_and_works_after_the_fix`.

**Owner questions added.** O-6: while bound, archives go to `<state>/backups/<vault id>/` on this Mac (covered by Time Machine with the key, not by a folder copy). Acceptable, or should the owner choose the location (and accept that a synced location reopens N2)? O-7: is typing the whole new code back the right confirmation, or would a shorter check (two groups) be enough?

**Tests added.** `crates/brokerd/tests/machine_lock.rs` (25, from 20): the two-phase bind and every way a prepare is abandoned; a crash in the commit before the rotation commits; the interrupted unbind and the vault identity; the backup after the key went away; an unbound vault still backing up into its own folder; the backup test now proves the archive is outside the vault folder and that no passphrase comparison happens. `crates/cli/tests/quick_cmds_cli.rs`: cancel, three wrong retypes, a wrong retype then the right one, the code printed once. `apps/desktop/tests/unit/machine-lock.test.ts` (18): the two steps, a wrong retype, closing between the steps, a commit after the prepared bind was forgotten, the new error text; `src-tauri/tests/bridge_ops.rs` (prepare, commit, cancel); `scripts/endpoint-matrix.py` (prepare, a commit with nothing prepared, the old code typed back, commit, the already-bound pair, cancel): 95 of 95 ops, 360 rows against the real daemon.

### ADR-165 third addendum · what the second re-review changed (2026-11-14)

The second re-review found no P0 or P1, confirmed N1–N4 and N6 fixed, and raised five P2 (M1–M5).

1. **M1, archives from before the bind leave the vault folder.** The commit (and every later bind on an already-bound vault) moves each `credmgr-backup-*.enc` from `<vault>/backups/` to `<state>/backups/<vault id>/`: a rename on the same volume, otherwise a durable copy and then the original removed; an archive whose name is taken there is left. The commit answers `archivesMoved` and `archivesNotMoved: [{file, reason}]`; while bound, `keystore.status` counts what is still in the folder (`inFolderArchives`) with a `warning`, and binding again moves it. This corrects the second addendum's "the same as any pre-bind copy": until moved, such an archive was carried by every copy of the folder, including copies made after the bind. What a copy made **before** the bind already held is unchanged.
2. **M2, a commit that dies before its rotation leaves no record that counts.** The commit still writes the record (with the pre-bind public keys) before the rotation, now marked `pending`, and clears the mark right after the rotation returns. A pending record counts only once the passphrase file is sealed, which happens only when the rotation committed; beside a plain file it is ignored (and dropped by the next prepare). So a crash there gives no false `plainWhileBound`, and the next passphrase change or recovery does not seal the vault the owner never finished binding. The bind's own rotation no longer writes a record of its own.
3. **M3, unbind fails cleanly when the record cannot be removed.** Removing the record returns its error (a missing record is fine); unbind then stops with the file still sealed, answering `internal` "the machine lock was NOT turned off (nothing changed)" and naming the state folder, instead of writing a plain file beside a record that would turn the lock back on at the next rotation.
4. **M4, a prepared bind belongs to the login that prepared it.** It keeps a SHA-256 of that login's token. Another login's commit (even with the shown code) or cancel is refused with `malformed_request` ("a bind is already waiting in another window or terminal"), and its prepare is refused while the first waits, unless that bind has expired or its login has ended. Locking the vault still forgets it.
5. **M5, disclosed.** The record is found through `vault.id`, a file inside the vault folder. Editing that file detaches the record (second addendum); so does putting the whole folder back to a state from before the bind, which has no `vault.id`, and that is not flagged at all (the path-keyed record of the first addendum did flag it as `plainWhileBound`). The lock itself still holds for everything written after the bind, because the root key was replaced; only the warning is lost. **Now reported (not repaired) by the fifth addendum below, 2026-11-20.**

**Tests added.** `crates/brokerd/tests/machine_lock.rs` (28, from 25): `the_commit_moves_pre_bind_archives_out_of_the_vault_folder_and_status_counts_any_left` (two pre-bind archives moved intact, a folder copy after the bind carries none, an archive put back and one whose move fails are counted and reported, binding again moves it); `an_unbind_whose_record_cannot_be_removed_fails_cleanly_and_leaves_the_lock_on`; `a_prepared_bind_belongs_to_the_login_that_prepared_it`; and the crash tests now assert no false `plainWhileBound` after a crash before the rotation, and that a passphrase change then leaves the vault plain.

**With the ADR-148 amendment (2026-11-20, the rc.2 merge).** A bound vault's backup now carries both the unsealed passphrase wrap (P0-2) and the restore ticket, never the rollback counter: `maintenance.backup` runs `create_backup_with_ticket_and_pass_wrap`. The ticket signs `registry.json` only, so the two compose: restored into an empty state directory, the archive writes the one-shot accept marker, and the first unlock with the passphrase checks it, writes the counter and consumes it. Held by `crates/brokerd/tests/machine_lock.rs::an_old_backup_of_a_bound_vault_opens_with_the_passphrase_after_a_rotation_and_a_lost_device_key` (the archive holds `_state/restore.ticket` and no other state file; the restore reports `AcceptMarker`; the unlock consumes the marker).

### ADR-165 fourth addendum · N5 closed: a passphrase change and a recovery re-key every live node (2026-11-20)

**What N5 was.** `vault.set_passphrase` (ADR-156) and `vault.recover` (ADR-163) rotated the root key but re-wrapped each node's private key rather than replacing it. A byte-copy of the vault folder from before the change, plus the OLD passphrase (or the used recovery code), still yielded the old root key, then the old node private keys, which open every envelope sealed to those same public keys later, entries written after the change included. Only `keystore.bind` re-keyed.

**Decision.** `rotate_root_locked` takes a `NodeKeys` argument: `Rewrap` (`maintenance.rotate_root`, and the bind's own rotation, whose bind re-keys afterwards with `node.rekey`'s protocol) or `Replace` (`vault.set_passphrase`, `vault.recover`). With `Replace` (`crates/brokerd/src/state/rotate/rekey_live.rs`) every live node gets a fresh X25519 keypair and everything it holds is opened with the old private half and sealed to the new public half by `rekey::reseal_node_files`, the code `node.rekey` itself now calls (refactored out of `rekey_node_durable`, unchanged in what it reads and refuses): the live entries, the note, the merge memory, every retained history slot and every removed entry still in its archive. Writes waiting in a node's locked-write tray are re-sealed too.

**How it composes with the staged commit: one stage, one record, nothing new to recover.** The new keypairs are drawn and every envelope re-sealed in memory before anything is staged. Each re-keyed node's NEW private key, wrapped under the NEW root, takes the place of its re-wrapped old key in the rotation's node-key set; its manifest rows take the new digests (one generation bump, as `node.rekey` makes); the registry names the new public keys; each history slot's and removed entry's signed record, which the rotation re-signs under the new root anyway, is re-signed with the new envelope digest in the same staged file (`rotation_history::resign_bytes_with_sha256`, `entry_archive::resign_bytes_with_sha256`). Every re-sealed envelope is then one more staged file under `rotation-pending/`, beside the manifests, node keys, registry, counter and wraps the rotation always staged, and the single atomic `COMMIT` record makes the whole set binding at once. ADR-076's key-free roll-forward moves every file before anything reads the vault, at start-up and at the top of every unlock and recovery. So a crash before the record leaves every file as it was (old root, old node keys, old passphrase, old code); a crash after it leaves every file new once the next unlock finishes the move (new root, new node keys); there is no third state, no second stage and no second record. The rotation's memory switch follows the commit as before, plus the new public keys, the new private keys into the hot set where the old one was live (a node locked on its own keeps its zeroised slot; `node.unlock` derives the new key from the new wrapped one), the new manifests, and the tray's digests.

**Which nodes, and the choices recorded.**
- *Live nodes:* every registry node but the orphan, global included, **and a node that is locked on its own** (the root key opens its wrapped key). Neither op refuses for a locked node or a full tray, unlike `keystore.bind`: refusing would turn a locked project into an owner who cannot change a leaked passphrase, or cannot get back in with the recovery code (the ADR-165 rule: no lockout for an owner with the passphrase or the current code).
- *Sealed nodes:* keep their keypair (the rotation re-wraps the archived key as before), as bind and `maintenance.rotate_root` treat them. Nothing is written to a sealed node; `node.restore` brings it back on that key, and `node.rekey` gives it a new one afterwards. **Disclosed:** a node sealed before the change and restored after it is on its pre-change key until re-keyed.
- *The orphan:* its cold keypair is replaced, exactly as the bind's rotation replaces it, when it holds no sealed copy; when it holds some, it is kept (re-sealed under the new root as before) and named in `notResigned` (`kind: "rekey-orphan"`). Re-sealing the orphan's sealed copies to a new cold key is not done here (open question N5-Q2).
- *A damaged file:* an envelope that does not open under its node's current key opened nothing before and opens nothing after; it is left exactly as it is and named in `notResigned` (`kind: "rekey-file"`, or `"rekey-tray"` for an untrusted tray file), never a refusal. A node whose wrapped key does not open under the old root still refuses the whole rotation, as the re-wrap always did; a node whose private key does not match its registry public key is re-wrapped as before and named (`kind: "rekey-node"`).
- *A `node.rekey` or `entry.move` stage this session could not clear* (its plan is sealed under the OLD root key; after any rotation nothing could open it and the next load would refuse the vault): every rotation now refuses up front with "lock the vault and unlock it again, then try again — nothing was changed". The next unlock settles such a stage. This closes a latent hazard for plain rotations and the bind as well.

**What is kept.** Grants (registry, no key material), the audit chain (one rotation record, now saying "N node keys replaced, M files re-sealed"), retained history and removed entries (re-sealed, nothing dropped), the Touch ID device wrap (re-sealed to the new root in the same commit, as before), the machine-lock state (a bound vault stays bound and sealed to the same device key; the bind record's pre-bind keys now match no live node, so `preBindNodes` stays empty), `vault.id`, and the restore ticket and marker (state-folder files the rotation never touches).

**Wire.** `vault.set_passphrase` and `vault.recover` answer two more fields: `nodesRekeyed` (the re-keyed node ids, sorted, as `keystore.bind` answers them) and `filesResealed` (a count). `maintenance.rotate_root` answers neither. No new op, error code or MCP tool.

**Cost.** Both ops are now O(entries + history + removed + tray), two fsynced writes per file (staged, then moved). Measured by `set_passphrase.rs::the_cost_of_rekeying_on_a_passphrase_change_measured` (an ignored test; debug build, this Mac, 2026-11-20): on a generated vault of 300 entries in 5 projects plus global, a plain `maintenance.rotate_root` took 1.40 s for 21 files and the re-keying passphrase change 7.62 s for 321 files, 300 of them re-sealed; both include one Argon2id passphrase proof and one Argon2id wrap. Roughly 20 ms per re-sealed file in a debug build; acceptable for an operation a person runs rarely and on purpose.

**Tests.** `crates/brokerd/tests/set_passphrase.rs`: `a_copy_from_before_the_change_plus_the_old_passphrase_opens_nothing_written_after_it` (the attack replayed offline from a byte-copy of the folder: the old node keys open nothing written after the change, no live envelope, and the old root opens no live node key; the copy's own contents still open, inherent; a locked node with a waiting tray write does not refuse the change; entries, note, history record, removed-entry record and restore, and the tray accept all work on the running broker and after a restart, `credmgr verify` clean), `a_crash_anywhere_in_the_rekeying_change_leaves_the_old_keys_or_the_new_ones` (every staging cut, before the commit, right after it and every roll-forward cut: old passphrase with every live envelope on the old node key, or new passphrase with none on it), and the cost measurement. `crates/brokerd/tests/recover_unlock.rs`: `a_copy_from_before_the_recovery_plus_the_used_code_opens_nothing_written_after_it` (the same attack from the used code and from the forgotten passphrase), and the existing crash tests now also check the node keypair: every staging cut and a crash before the commit leave the entry on the old node key; every post-commit cut leaves it on the new one. `crates/brokerd/tests/presence.rs::touch_id_unlock_survives_a_rekeying_passphrase_change` (the software stand-in helper: Touch ID opens the vault on a fresh daemon after the change and the re-keyed entry reads). `crates/brokerd/tests/machine_lock.rs::rotation_and_a_passphrase_change_while_bound_reseal_to_the_same_key` now also asserts the re-key and that the bound vault, after a restart, unlocks with the new passphrase and reports bound, opening here, record attached, no pre-bind node, no warning. `rekey.rs`, `rotate_root.rs` and the rest of `machine_lock.rs` are unchanged and green over the refactor.

**Open questions (conservative choice taken).** N5-Q1: should `maintenance.rotate_root` re-key too? Left re-wrapping (ADR-076's contract and its whole-vault file-diff test say envelopes are untouched); a rotation run because the root key leaked has the same gap, and the change is one argument. N5-Q2: re-seal the orphan's sealed copies to a new cold key instead of keeping the cold key when it holds some.

### ADR-165 fifth addendum · M5: a detached bind record is reported, never repaired (2026-11-20)

**What M5 was.** The bind record is found through `vault.id`, a file inside the vault folder. Editing it, or putting the whole folder back to a state from before the bind (which has no `vault.id`), detached the record silently: the lock still held for everything written after the bind, but `plainWhileBound` and `preBindNodes`, which are read through the record, were lost without a word.

**Decision.** `BrokerState::detached_bind_record` looks through this Mac's records (`<state>/machine/vaults/*.json`) for one written for this vault folder (its `vault` path, compared as written and canonicalised) under a vault id that is not the one `vault.id` holds now (or `vault.id` is missing or not a valid id). A vault whose current id has its own record is attached, and a `pending` record (a bind whose rotation never committed) is not counted. When found:
- `vault.status` carries `warnings: ["machine_lock_record_detached"]`, the additive list other replies use (`push_warning`), **to the owner's own login only** (as `anomaliesUnseen`); an agent, or a caller with no login, never sees it (ADR-165 §5: an agent may not learn whether a vault is tied to this Mac).
- `keystore.status` answers `recordDetached: true` and its `warning` sentence (said before the others, since they are read through the record; kept under the app's 300-character caption limit): the record's id and the folder's, what can cause it, that nothing was repaired, and that what was written after the lock stays protected.
- `credmgr status` prints a `machine lock warning:` line; `credmgr keystore status` prints the warning, as it prints the others.
- The app shows it where the other machine-lock warnings show: the Settings › Security › Machine lock row's caption, with a `warn` chip.
- One audit record (`system:keystore` / `keystore.bind_record_detached`, the two ids, no secret) is written the first time the owner's status finds a given detached state while the vault is open; the record remembers the vault id it was audited under (`detachedNoticed`), so further status reads do not write again, and a new detached state (an edited id, then a removed one) is audited once more.

**No auto-repair.** Nothing rewrites `vault.id`, the passphrase file or the record's identity; the warning goes away when `vault.id` is put back, or when the owner unbinds and binds again. **Known limit:** a different vault created or restored at the same path, with this Mac's state folder, is indistinguishable from an edited `vault.id` and is reported too (the sentence names that case); the test of the second addendum that asserted "no warning" there now asserts the detached report.

**Tests.** `crates/brokerd/tests/machine_lock.rs`: `a_detached_bind_record_is_reported_to_the_owner_audited_once_and_never_to_an_agent` (an edited `vault.id`: the owner's `vault.status` warns, `keystore.status` says it, one audit record across three reads, an agent's `vault.status` carries no `warnings` and writes no audit record, nothing repaired; a removed `vault.id`: warned and audited once more; put back: silent), `no_detached_warning_for_an_unbound_vault_or_another_folders_record`, and `an_interrupted_unbind_never_turns_the_lock_back_on_and_the_record_follows_the_vault_not_its_path` updated as above. App: `apps/desktop/tests/unit/machine-lock.test.ts` (the caption and chip).

### ADR-165 sixth addendum · N5-Q1 and N5-Q2 closed by the operator (2026-11-20; ADR-174)

**Decided.** The operator took both open questions of the fourth addendum on 2026-11-20 (recorded as ADR-174 items 7 and 8): **N5-Q1** "Rotating the root key also replaces every project key", and **N5-Q2** "Sealed copies of removed projects are re-sealed to a new key on re-key".

**N5-Q1, built.** `maintenance.rotate_root` takes `NodeKeys::Replace`, like `vault.set_passphrase` and `vault.recover`; only the bind's own rotation keeps `NodeKeys::Rewrap` (its bind re-keys right after). Everything this addendum's fourth predecessor says of the re-key now holds for a plain rotation too: the same nodes (live, global, a node locked on its own), the same treatment of a damaged file (left and named, `kind: "rekey-file"`), the same refusal of a leftover `node.rekey` or `entry.move` stage, the same answer fields (`nodesRekeyed`, `filesResealed`). ADR-076's contract and its file-diff test are amended accordingly (ADR-076 amendment).

**N5-Q2, built.** On every re-keying rotation (a plain one, a passphrase change, a recovery) the orphan's cold keypair is replaced **even when it holds sealed copies**. `BrokerState::plan_orphan_reseal` (`crates/brokerd/src/state/rotate/rekey_live.rs`) opens the current cold key under the old root (it must match the orphan public key the registry names), draws a new cold keypair sealed under the new root, and re-seals every sealed copy with `rekey::reseal_node_files`; the new cold file, the re-sealed copies, the orphan manifest (new digests, one generation bump) and the registry's new orphan public key are staged together and bind at the one `COMMIT` record. `orphanKeyReplaced` in the outcome is now true whenever the cold key was replaced. A sealed copy that does not open under the old cold key is left and named (`kind: "rekey-file"`); a cold key that does not open, or does not match the registry, is kept (re-sealed under the new root, as before) and named (`kind: "rekey-orphan"`). The `kind: "rekey-orphan"` entry that said "holds N sealed copies, so its cold keypair was kept" is gone. Seal records are untouched (they name the orphan rows by id, not by digest), so `node.restore` inside the window works as before, and the human-only `orphan.reveal` opens the re-sealed copies with the new cold key.

**Not changed.** `keystore.bind` still refuses while the sealed entries hold anything (its preflight, second addendum); its rotation would now re-seal them like the others, so lifting that refusal is a separate, small decision for the owner of the bind flow. A sealed node's archived envelopes keep their keypair, as before.

**Tests.** `crates/brokerd/tests/adr174_rekey.rs`: `a_copy_from_before_a_root_rotation_plus_its_root_key_opens_nothing_written_after_it` (N5-Q1's attack replayed through the wire, with `nodesRekeyed` and `filesResealed`), `a_crash_anywhere_in_a_rekeying_rotation_leaves_the_old_keys_or_the_new_ones` (with the sealed copies and the orphan reveal checked at every cut), `sealed_copies_are_resealed_to_a_new_orphan_key_and_still_reveal_and_restore` (the old cold key opens no copy after a rotation or a passphrase change, the new one opens every copy, `orphan.reveal` works before and after a restart, the sealed node restores, `credmgr verify` clean). `crates/brokerd/tests/rotate_root.rs` amended where it asserted the old contract (the public keys, the audit detail, the file diff, the orphan keypair).

### ADR-165 seventh addendum · the owner questions O-1..O-5 closed by ADR-174 (2026-11-20)

The operator answered the five owner questions of the first addendum on 2026-11-20 (recorded as **ADR-174**). Each is closed here, with what was built (lane D2, branch `feat/adr174-d2`).

1. **O-1, closed: "A backup of a locked vault still restores on another Mac with passphrase + recovery code, so a dead Mac never means lost data."** The behaviour already held (P0-2's unsealed wrap inside the archive, the ADR-148 amendment's restore ticket), so nothing changed in the code. A test now pins the recovery-code half on a Mac with no device key: `machine_lock.rs::a_backup_of_a_bound_vault_restores_on_another_mac_with_the_passphrase_or_the_recovery_code` (the archive restored on one fresh Mac opens with the passphrase of its day, on another with `vault.recover` and the code of its day; neither path reads or makes a device key; the restored vault is not bound until bound again there).
2. **O-2, closed: "Keep the Mac-bound device key out of Time Machine."** This reverses the first addendum's P1-3 decision. The exclusion is Time Machine's sticky one, the attribute `com.apple.metadata:com_apple_backup_excludeItem` holding the binary property list of `com.apple.backupd` (61 bytes, byte for byte what `tmutil addexclusion` writes, checked against it by a test), set and read back through `/usr/bin/xattr` with fixed arguments and the path only (the workspace forbids `unsafe`; no shell). **Born excluded:** a new key gets the attribute on its temporary file before the hard link puts it at its path (the attribute is on the inode), so it is never at `lock.key` un-excluded, and `<state>/machine/lock.key.provenance.json` (key id + `bornExcluded`, written durably before any wrap is sealed under the key) records it. **Re-asserted** at every bind and every passphrase unlock of a sealed vault. **Never fatal:** a failure is logged name-free in the diagnostic log (`machine_lock_time_machine_exclusion`, a static reason) and `keystore.status` answers `deviceKeyTimeMachineExcluded: false` with a warning. **An older key (the security review of the first O-2 build):** a key with no provenance saying it was born excluded (made before ADR-174, or its exclusion failed) may already be in Time Machine; binding a plain vault on a Mac with Time Machine puts it aside — excluded, then renamed to `<state>/machine/retired/<key id>.key`, never deleted — and seals under a fresh born-excluded key (`deviceKeyReplaced: true`). Crash-safe because the vault is plain until the bind's rotation commits. Not done when another vault's bind record on this Mac may need the old key (several vaults can share a state folder): the key is kept and excluded from then on. **Claimed only when true:** `deviceKeyTimeMachineCovered` is set only for a bound vault sealed to a key born excluded and still excluded; `protects` names a Time Machine backup only then, and `doesNotProtect` otherwise says Time Machine backups may hold the key and how to replace it (turn the lock off and on again). What it costs, accepted with the decision: a Time Machine snapshot of a bound vault folder older than the last rotation now opens only with the recovery code of its day (CredMgr backups are unaffected, O-1). Whole-disk images and Migration Assistant still carry the key. The retired key file is not read by the broker; a copy sealed under it opens with the recovery code of its day.
3. **O-3, closed: "Refuse to lock a vault folder that two Macs share (iCloud/Dropbox)."** `keystore.bind` refuses a plain vault whose folder (as written or resolved) is under `<home>/Library/Mobile Documents` (iCloud Drive), `<home>/Library/CloudStorage/<provider>` (Dropbox, Google Drive, OneDrive, Box; named by the folder's prefix, never its account part), under a `.dropbox` marker in the folder or a parent, or under a folder carrying a `com.apple.fileprovider*`, `com.apple.file-provider*` or `com.apple.icloud*` extended attribute (how iCloud's Desktop & Documents sync marks `~/Desktop` and `~/Documents`). Checked at `prepare` before anything is proven, drawn or written, and again at `commit` (a folder that became synced in between; the prepared bind keeps waiting). **No new error code:** the refusal is `malformed_request` with its own words ("the machine lock was not turned on (nothing changed): the vault folder is in …, which another Mac can open too …"), following the device-key-inside-the-vault precedent, so `error.rs`, `BrokerErrorCode` and the counts are unchanged. A vault already bound is not refused (its "bind again" only finishes re-keying); `keystore.status` answers `syncedFolder` and warns for one. The home folder is injectable in tests (`BrokerState::set_sync_home_for_test`).
4. **O-4, closed: the stable key id stays.** No owner decision was needed beyond this addendum's default: **default kept per ADR-174**. The 8-byte id reveals nothing about the key.
5. **O-5, closed: "Turning the machine lock on needs Touch ID or your authenticator code."** Each phase of `keystore.bind` that can change the vault — `prepare`, and a `commit` that would go past its own checks (this login's bind, unexpired, under the current root key) — needs a presence proof for exactly that request where a presence key is enrolled (`presence_required` / `presence_failed`; the presence challenge now issues for `keystore.bind`, "Turn on the machine lock"), otherwise a fresh vault second factor where a gate is enrolled (`two_factor_required`). With neither enrolled, today's requirement stands and is the whole of it: the passphrase and the current recovery code at `prepare`, the new code typed back at `commit`. `cancel` never asks. Every refusal that needs no finger (a missing parameter, a locked vault, a synced folder, nothing prepared) comes first, so it never costs a prompt; a missing proof changes nothing and keeps the prepared bind, so a commit typed after the five-minute window closed works once the factor is given again. `keystore.status` answers `bindProof` (`"presence"`, `"secondFactor"`, `"none"`). The shell attaches Touch ID proofs as it does for every presence-gated op (twice: prepare and commit); the app's bind dialog shows an authenticator-code field when `bindProof` is `secondFactor` (stepped up with `vault.gate_verify` before `prepare`) and asks for a fresh code at the confirm step when the commit answers `two_factor_required`; the CLI asks for the authenticator code on the next stdin line when a phase answers `two_factor_required`. `keystore.bind` is not added to the report's "presence every time" list (its `cancel` never asks, and the audit record cannot tell the phases apart).

**Tests added.** `crates/keystore/src/machine_lock.rs` (11, from 7): the exclusion value equals `tmutil addexclusion`'s and Time Machine reads it; a new key is born excluded with its provenance and an older key is retired, not deleted; iCloud Drive, CloudStorage providers (no account in the label), a symlink into iCloud Drive and a `.dropbox` marker are found; a File Provider or iCloud attribute on a parent is found. `crates/brokerd/tests/machine_lock.rs` (37, from 30): O-1 above; `the_device_key_is_kept_out_of_time_machine_at_bind_and_again_at_every_unlock`; `an_existing_device_key_that_may_be_in_time_machine_is_replaced_at_bind_or_never_claimed`; `bind_refuses_a_vault_folder_that_a_sync_service_shares_with_other_macs`; `bind_refuses_a_vault_under_a_folder_a_file_provider_marks`; `turning_the_lock_on_needs_touch_id_for_each_phase_where_a_presence_key_is_enrolled`; `turning_the_lock_on_needs_a_fresh_second_factor_where_one_is_enrolled_and_no_touch_id`; the older tests that bind with a presence key enrolled now attach the proof a client attaches. `apps/desktop/tests/unit/machine-lock.test.ts` (23, from 19): the Time Machine caption only for a covered key, the synced-folder caption and disabled Bind, the second-factor steps, the Touch ID note. **Not done:** a CLI integration test of the authenticator prompt (the broker's refusal and the app's flow are tested); the controls are tested against the fixture broker, not pressed in a built app.

## ADR-166 · Restore from the app; restore refuses while the broker runs (2026-11-20)

**Context.** `credmgr restore` (ADR-112) is the only way back from a backup, and the app had no door to it: ADR-151 §4 declined the design drop's "Restore from backup" row because there is no broker op for a restore and there cannot be one (a restore writes a vault and its generation counter, which a running broker owns). ADR-148 deferred "refuse `credmgr restore` while the broker runs"; ADR-156 (K-23 (d)) then made the command refuse when a broker answers on the vault's socket, inline in `cmd_restore`. rc.2 §1 item 2 asks for Restore in the app, refusing while a broker runs, with the CLI and the app sharing one check and one implementation, and no crypto or file swapping written twice.

**Decision.**

1. **The app runs the command line; it does not restore anything itself.** A new shell command `backup_restore {archive, passphrase, target?}` (`src-tauri/src/restore.rs`, a `SHELL_COMMANDS` row: local, no broker op, no session, no audit record) runs `credmgr restore <archive> [--to <target>] --json`, writes the backup passphrase to the child's stdin (never argv; the shell's copy is a `Zeroizing<String>`), and reads back one JSON object. So there is exactly one restore and one set of refusals, the command line's, and the shell still links no crypto crate: ADR-035 keeps `credmgr-store` and `credmgr-keystore` out of the `src-tauri` workspace, and ADR-001's "the shell decrypts nothing" holds (the archive's passphrase layer is opened in the `credmgr` process, which writes the still-sealed vault files and exits).
2. **`credmgr restore --json`.** New flag. On success it prints `{restored: true, target, stateDir, files, bytes, counter: "restored"|"keptExisting"|"notInArchive", complete}`; on any refusal `{error, message}` and exit 1. The codes: `broker_running`, `restore_target_not_empty`, `restore_failed` (a wrong passphrase, a damaged or unreadable archive, a usage error, any `restore_bundle` refusal). Without `--json` the output is as before.
3. **The shared check.** `restore_refusal(target, sockets)` in `crates/cli/src/main.rs`, run before the passphrase is read: the target must be empty or new, then no broker may answer on the vault's socket **or the target's own** `run/broker.sock`. A live connection is a running broker; a socket file nobody listens on (a broker that died) does not block. It is the check the terminal and the app both go through, because the app runs the terminal's command; no shared crate is needed for it (the alternative, moving it into `credmgr-store` and linking that crate into the shell, is what ADR-035 rejects).
4. **Where the app finds `credmgr`.** The places Start at login looks for `credmgrd` (ADR-157), in the same order: beside the app's executable in `Contents/MacOS`, `../Resources`, `../libexec`, `/usr/local/bin`, `/opt/homebrew/bin`. `CredMgr.app` now carries `Contents/MacOS/credmgr` (`tauri.conf.json` `bundle.macOS.files`; `scripts/release-app.sh` builds it with `credmgrd`, stamped the same way). No environment override: a variable naming the program to run would be a second way to make the window execute something.
5. **Four bridge-local codes** (`error.rs` `BRIDGE_LOCAL_CODES`, `bridge.ts` `BridgeLocalCode`): the command's three, passed through verbatim (an unknown code becomes `restore_failed`, never something else), and `restore_unavailable` when no `credmgr` program was found. No broker error code is added (27 stay).
6. **The screens.** Settings › Backup gains "Restore from a backup" with Restore…; the broker-unreachable screen gains "Restore from a backup…". One dialog (`dlg-restore.html`, outside the unlocked app so the broker-down screen can open it): the archive's path, the folder to restore into (empty means the vault's own folder, which must then be empty), the backup passphrase, what a restore does, and, while this window is connected to a broker, a note that a restore from here is refused and what to do. A refusal is said next to the form in words chosen by the app (`errors.ts`), never the command's message; `broker_running` says to quit CredMgr (and turn off Start at login or stop `credmgrd`) and restore in a terminal. A finished restore lists what was written, the counter outcome, an old-format warning and the next steps; the passphrase is dropped as soon as the call returns and the form is wiped on every way of closing.
7. **No file picker.** The Tauri dialog plugin is not a dependency and is not added for this (no new plugin surface for one row); the paths are typed.

**Supersedes** ADR-151 §4's "the window must not offer one" for restore only: the window still offers no broker op for a restore; it offers the offline command, which refuses beside a running broker.

**Alternatives rejected.**
- Linking `credmgr-store` and `credmgr-keystore` into the shell and calling `decrypt_with_passphrase` + `restore_bundle` directly: it pulls the crypto tree and its MSRV pin across ADR-035's boundary and puts decryption in the shell process (ADR-001).
- A broker op `maintenance.restore`: a running broker is exactly what a restore must not run beside.
- A shell-side socket probe before running the command: a second implementation of the refusal; the command's own check runs first anyway and answers before the passphrase is read.

**Known limits.** While this window is unlocked a broker is running, so a restore from Settings is always refused there; the broker-unreachable screen is where it goes through. The restored vault is in the folder chosen; pointing the broker at it (or restoring into the vault's own empty folder) is the person's step, said in the result. `release-lib.sh` does not yet check that the app carries an executable `credmgr` (it checks `credmgrd`); tracked for the release verifier. **Integrator note:** numbered ADR-166 by the rc.2 app lane; another rc.2 lane may have taken the same number, in which case renumber this one.

**Tests.**
- `crates/cli/src/main.rs::a_restore_is_refused_for_a_used_target_or_a_live_broker_and_not_for_a_dead_socket`.
- `crates/cli/tests/restore.rs::json_mode_prints_one_object_for_the_app_and_names_each_refusal_by_code` (with the existing refusal test).
- `src-tauri/src/restore.rs` unit tests (4) and `src-tauri/tests/backup_restore.rs` against the real `credmgrd` and `credmgr`: refused with `broker_running` while the broker runs, nothing written; once it stops, a wrong passphrase is `restore_failed`, the restore writes the vault and its counter, a second one is `restore_target_not_empty`, and the restored vault unlocks.
- `src-tauri/tests/shell_config.rs::the_app_bundles_the_command_line_where_restore_looks_first`; `ts_client.rs` and the drift guards (93 bridged + 18 shell commands).
- `apps/desktop/tests/unit/restore.test.ts` (6), `tests/e2e/rc2-app.spec.ts` (item 2, both engines), `tests/real/rc2-app.spec.ts` (the real command refuses beside the real broker); the real-broker shim runs the built `credmgr` for `backup_restore`.

## ADR-167 · Entry tags: free-text labels on the manifest row, read like names, set by the owner only (2026-11-20)

**Context.** V1 had tags (`v1/lib/store.js`: an array of strings per credential, set on create and update, `list --tag` matched one exactly, the fuzzy search scored them). V2 had none, so a V1 import (`tools/v1-to-v2/migrate.js`, ADR-097) dropped them and the owner had no way to group entries across the free-text name space inside a node. rc.2 §3 item 1 asks for V1 parity. The constraint is the boundary: a tag must not become a way to find or count entries in a node the caller cannot list.

**Decision.**

1. **A tag is per entry, free text, normalised** by `credmgr_core::tags` (pure, I/O-free): surrounding white space trimmed, lower-cased (Unicode), every run of inner white space turned into one `-`; what is left is 1 to 32 characters, each a letter or digit of any script or one of `-` `_` `.` `:` `/`. At most 16 tags per entry; two spellings that normalise alike are one tag (first kept, in its normalised form). Anything else is `malformed_request` naming the index, never the text.
2. **Stored on the entry's signed manifest row** as `tags`, written only when non-empty (`skip_serializing_if`), so every manifest written before this ADR re-serialises byte for byte and still verifies (the alpha.6 golden tests stand). Names-level metadata, like the name and the aliases (ADR-121): it travels with `entry.move` (ADR-158) because it is on the row, it is in the removal archive's snapshot because the snapshot is the row, and it is in a backup because the manifest is.
3. **Who reads a tag:** whoever may list the node. `entry.get` carries `tags` when there are any; `entry.list`'s metadata rows (human sessions, ADR-077) carry them. A node that hides its names from the caller (`privateNames`, ADR-083) hides its tags too: `entry.get` drops the key and a filtered `entry.list` is refused with `node_access_denied` rule `private_names`, as a name search is, because a filtered count would say what a tag is on.
4. **Not a cross-node index.** `tag` is a filter on `entry.list {node, tag}` and `entry.search {node, term, tag}`: it narrows the entries of the one node the request names, among exactly those the caller could already list there. There is no vault-wide tag query, no tag list op and no tag in `search` (the cross-node name search) or in `graph.snapshot`. Even the owner asks one node at a time. The MCP tool `credmgr_list` advertises the optional `tag` (an agent that may list a node may filter it, as it may read its names); no tool sets a tag.
5. **Who sets a tag: the owner's sessions only, as aliases (ADR-121 §3).** `entry.tag_set {node, entry, generation, tags}` replaces the whole set (`[]` clears). `update` capability on the node (a locked node refuses, R1), the node's write lock, F-9's generation check; metadata only (the envelope is neither read nor rewritten). An `Origin::Agent` scope (an agent session, a cwd-scoped process, an agent token) is refused with `capability_not_held` whatever it holds. No MCP tool maps to it; like `entry.alias` it is not on `FORBIDDEN_OPS` (no tool exists to forbid, and the broker refuses agents itself). Answers `{node, entry, generation, tags}`.
6. **Audit:** the generic per-request record (`entry.tag_set`, the node, the entry, the new generation). No tag text is recorded: a tag can be as telling as a name, and audit records carry neither (ADR-134).
7. **Surfaces.** CLI `credmgr tag <name> [--node <id>] [--add <t>]… [--remove <t>]… [--clear]` (reads the entry, edits the set with `credmgr_core::tags::edit_tags`, sends one `entry.tag_set`; with no flag it prints the tags) and `credmgr list --node <id> --tag <t>`. Desktop: bridge command `entry_tag_set`; the entry inspector shows the tags as chips under the name with an editable field (Enter adds, ✕ removes), each change one `entry.tag_set` with the node's generation, re-reading the entry after (the ADR-157 expiry-chip pattern).

**Alternatives rejected.** A vault-wide tag index or `tag.list` op (an index across boundaries is exactly what the node model forbids, and a list of tags is a map of the vault); case-sensitive tags as V1 had (`Prod` and `prod` as two tags is a bug V1's users hit); tags in the sealed envelope (a filter would then need every value opened; tags are labels, not secrets); letting agents tag (ADR-121 keeps naming with the owner, and an agent that can tag can make entries findable by its own words); recording tag text in the audit trail.

**Open questions (operator).** (a) Agents see an entry's tags through `entry.get` (as they see aliases) but not on `entry.list` rows (ADR-077 keeps list metadata human); whether agents should get them on list rows is left as it is. **Settled by ADR-174 (2026-11-20): yes** — an agent that may list a node sees each listed entry's tags on `entry.list` (a `tags` map `{<entry id>: [...]}`, only when some entry has tags; never another node's, never on a `privateNames` node). Test `tags.rs::an_agent_sees_the_tags_of_the_entries_it_lists_and_no_others`. (b) V1's fuzzy search scored tags; V2's `entry.search` matches names and aliases only and uses a tag as an exact filter.

**Tests.** `crates/core/src/tags.rs` (4); `crates/brokerd/tests/tags.rs` (5: normalise, replace, clear, list, get, search and a restart; limits, bad tags, a stale generation, a missing entry; agents refused but may filter; a filter never returns another node's entries; a node hiding its names hides its tags); `crates/cli/tests/quick_cmds_cli.rs::tag_adds_removes_clears_and_list_filters_by_tag`; `src-tauri/tests/bridge_ops.rs` and `drift_guards.rs`; `apps/desktop/tests/unit/tags-merge.test.ts`.

## ADR-168 · `merge.*`: suggestions and merges inside one node, values compared only in the broker, every merge undoable (2026-11-20)

**Context.** V1 had a merge engine with a decision memory (`v1/lib/store.js` `findMergeSuggestions`, `dismissSuggestion`, `merge`, `autoMerge`, `autoMergeAll`; `18_ENDPOINT_INDEX.md` rows 144–151 carried the eight V2 names as `planned`). ADR-161 deliberately left `merge.*` out of the doctor's first phase: its findings propose `merge` and `rename_or_merge` for copies in one node but apply none. rc.2 §3 item 2 asks for the merge actions. V1 compared every value in the vault in one process; V2 must not let a merge cross a boundary, show a value, or persist anything derived from one in the clear.

**Decision.**

1. **One node per request, never across a boundary.** Every `merge.*` op names one `node`; suggestions compare entries of that node only, `merge.apply` refuses an entry id that is not in it (`not_found`, the same answer as a bogus id), and nothing is ever proposed between two nodes even when their names and values match (`isolation.rs::merge_never_crosses_a_node_boundary`). Copies in different nodes stay the doctor's `share` proposal (ADR-161), which is not a merge.
2. **Who: the owner's login with `Admin` on the node** (`owner_session`, `human_admin_on`), for all eight. An agent session, an agent token, a cwd-scoped process and the CLI's non-login scope are refused with `capability_not_held`. The orphan node is refused (`malformed_request`); a locked node answers `node_locked` (suggestions need values; the decision memory is sealed to the node's key). **All eight are on `FORBIDDEN_OPS`** and no MCP tool maps to any: even a names-only suggestion of kind `identical` says that two entries hold the same value, which is a fact about values, and the decision memory is the owner's judgement.
3. **Suggestions (`merge.suggestions {node, includeDismissed?}`).** Read-only. Three kinds, strongest first: `identical` (every entry of the group holds the same multiset of field values, so dropping all but one loses no value), `shared_value` (at least one field value in common), `similar_names` (names one separator, case or edit apart: `credmgr_core::names::similar_names`, the rule of `entry.similar`, ADR-121). Values are opened one entry at a time inside the broker and digested with **HMAC-SHA256 under a 32-byte key drawn for this call and dropped when it returns** (`credmgr_core::doctor::ScanKey`, the ADR-161 rule): no value, digest, length or fragment leaves the broker, is logged or is stored, and two calls use two keys. Values under 8 characters and placeholders are not compared (`skip_for_duplicates`). Values are compared only where the caller could reveal them without being asked for more; a node whose own second factor is not open is compared by name only and says `valuesCompared: false`. Each suggestion is `{key, kind, reasons[], entries:[{entry, ref, name}], keep, identical, dismissed?}`, where `key` is the group's entry ids sorted and joined with `+`, and `keep` the proposed survivor (the lowest `ref`, the oldest entry, as V1 kept the lowest source ref). At most 2,000 entries are read and 200 suggestions answered (`truncated`). Dismissed keys are left out unless `includeDismissed: true`.
4. **`merge.apply {node, keep, drop[], generation}`** keeps one entry and removes the others **through the `entry.remove` path**, so each is in its 7-day archive and `entry.undo` brings it back. `drop` is 1 to 19 distinct ids, none equal to `keep`, all in the node. The kept entry gains every dropped name and every dropped alias as aliases (V1 4.1 "aliases preserved", ADR-121's name space, so `credmgr` resolves the old names to the kept entry) and the union of the tags (ADR-167). Refusals, all before any factor is asked for: a stale generation `conflict`; a missing id `not_found`; more than 8 aliases or 16 tags on the kept entry `malformed_request` (merge fewer at a time); **an entry-level grant on a dropped entry `malformed_request`** (revoke it first, or keep that entry: unlike `entry.move` the grant is not revoked silently, because a revoked grant is not brought back by an undo). Then a fresh second factor (the vault's, and the node's own where it has one: `require_fresh_factors_for`); no presence proof, since the change is undoable for seven days, as `entry.remove` is. **The generation and the plan are checked again under the node's write lock**, held from that check to the last manifest change: a write that landed while the request waited for its factor or the lock makes it `conflict` and writes nothing; a dropped entry is archived first, the kept entry's row changed next and the dropped rows removed last, and any failure puts the archived envelopes back with no row changed. `merge.auto` and `merge.auto_all` commit the same way, at the generation the suggestion pass read (all of `auto_all`'s groups under one hold of the lock). Answers `{node, keep, merged:[{entry, name, undo}], aliasesAdded[], tagsAdded[], generation}` where `undo` is the audit id `entry.undo` takes. Never a value.
5. **Undo strips what the merge added.** Each dropped entry's removal archive records `mergedInto: {entry, aliases}` (signed with the archive; written only for a merge, so older archives verify as before). Restoring it (`entry.undo` of its `entry.remove` record, or `entry.restore`) first takes those aliases off the kept entry, where it still holds them, so the restored entry gets its own name back instead of `keep-both`'s `"<name> old"`; then it is restored with its own aliases and tags. **Tags the merge added to the kept entry stay** (a tag may have been on both; the owner removes one with `credmgr tag --remove`).
6. **The decision memory: `merge.dismiss {node, key}`, `merge.undismiss {node, key}`, `merge.dismissed_list {node}`, `merge.restore_all {node}`.** A dismissed key never comes back in suggestions until undismissed or restored. The key must name 2 to 20 entry ids, sorted, all currently in the node. The memory is **per node, sealed to the node's key** in `nodes/<id>/merge.env` (envelope id `merge-memory`), with its SHA-256 recorded in the node's signed manifest (`mergeSha256`, written only when there is a memory), exactly as a node's note is (ADR-072): an older file put back over it is refused, a backup carries it, `node.rekey` re-seals it with the node's other files (a plan item kind `merge_memory`), and sealing or restoring the node moves it with the directory. Sealed rather than plain on the manifest because a dismissed `identical` group says two entries share a value. At most 1,000 keys per node. Each change moves the node's generation (a node write, F-9) and answers it. `dismissed_list` answers `{key, entries:[{entry, name|null}], dismissedAt}` (`null` for an entry no longer in the node). `restore_all` answers the count.
7. **`merge.auto {node, key, generation}`** applies one suggestion **only when it is `identical`**, keeping its proposed `keep`; any other kind, a dismissed key or a key that is no longer suggested is `malformed_request`. **`merge.auto_all {node, apply?, generation?}`** plans every undismissed `identical` suggestion: **a dry run by default** (writes nothing, asks for no factor) answering `{dryRun: true, planned:[…], skipped:[…]}`; with `apply: true` it needs `generation` and a fresh second factor, applies each planned group in turn through the `merge.apply` path and answers `{dryRun: false, planned, merged, skipped, generation}`. A group with a grant on a dropped entry is `skipped` with reason `grant`.
8. **Audit.** The generic per-request record of every op (the node, the new generation; never the key, never a name). Each merged group adds one `entry.remove` item event per dropped entry (detail `merged into <keep>`; its id is the `undo` id) and one `merge.apply` item event on the kept entry (detail `kept; absorbed <n>`). No value, digest or name in any record.
9. **Refusals with existing codes (the 27 stay).** `malformed_request`, `capability_not_held`, `not_found`, `conflict`, `node_locked`, `two_factor_required`, `vault_locked`.
10. **Surfaces.** CLI `credmgr merge suggest|apply|dismiss|undismiss|dismissed|restore-all|auto|auto-all` (`--node`, `--keep <name>`, `--drop <name>`…, `--group <key>`, `--apply`, `--json`); `auto-all` is a dry run unless `--apply`. Desktop: eight bridge commands; the Tidy up screen (ADR-161) gets **Merge** and **Dismiss** on a same-node shared-value finding: Merge sends `merge.apply` keeping the oldest entry of the finding (the lowest reference, the broker's own `keep` rule) with the node's generation (a missing second factor is said and goes to the app's step-up); Dismiss sends `merge.dismiss` with the group's key (its entry ids sorted and joined with `+`, as `merge.suggestions` keys it); either runs the scan again. The entry inspector shows the tags as chips (ADR-167).

**Alternatives rejected.** Suggestions across nodes (a merge across a boundary moves a value into another scope; that is `entry.move`'s job, with its gates); a persisted value hash for faster suggestions (it would let two reports, or a report and a guess, be matched); revoking grants as `entry.move` does (an undo could not bring them back); deleting dropped entries outright (V1 4.1 kept them recoverable; the 7-day archive is that); a plain-text dismissal list on the manifest (a dismissed identical group is a fact about values); a `merge_conflict` error code (the existing codes say every refusal); letting agents read suggestions (see 2).

**Open questions (operator).** (a) Whether `merge.auto_all` should also apply `shared_value` groups V1 called safe by its field-label heuristics; it does not (conservative: identical only). (b) Whether a dismissed key should follow an entry that `entry.move` takes to another node; it does not (the key then names an entry not in the node and shows `null`). (c) Whether a merge should carry the dropped entries' field values into the kept entry as extra fields (V1's structured merge); it does not: the kept entry's fields are unchanged and the dropped values stay recoverable in the archive for seven days.

**Tests.** `crates/brokerd/tests/merge.rs` (6, among them a write landing while a merge waits for the node's lock, which is `conflict` with nothing merged or archived); `crates/brokerd/tests/isolation.rs::merge_never_crosses_a_node_boundary`; `crates/store/src/entry_archive.rs` (the `mergedInto` record round-trips and an archive without it re-serialises as before); `crates/mcp/tests/i13_tool_registry.rs::every_merge_op_is_forbidden`; `crates/cli/tests/quick_cmds_cli.rs::merge_suggests_dismisses_and_auto_all_is_a_dry_run_until_apply`; `src-tauri/tests/bridge_ops.rs` and `drift_guards.rs`; `apps/desktop/tests/unit/tags-merge.test.ts`.

## ADR-169 · `vault.doctor_apply`: apply every move of one doctor plan in one request, stopping at the first failure (2026-11-20)

**Context.** ADR-161 left "a one-step apply the whole plan" as a later phase: the tidy-up scan proposes moves (a misfiled entry to its project, one copy of a value two sub-nodes share to their parent), each with the exact `entry.move` parameters, and the owner applies them one at a time, each asking again for a code and Touch ID. A vault tidied for the first time can carry dozens. The rc.2 leftover list (lane L2) asks for a way to apply them all at once that never does anything the person did not see. **Integrator note:** numbered ADR-169 by lane L2 because 162–168 were taken by other lanes when it was written; renumber if needed.

**Decision.**

1. **The request carries the plan; nothing is looked up.** `vault.doctor_apply {moves: [{node, entry, to, generation}], reason?}` takes 1 to 500 moves (the doctor reports at most 500 findings of a kind), each exactly a scan proposal's `move`. `generation` is the source node's as the scan read it. There is no scan id and the broker keeps no plan: a report lives only in the client's memory (ADR-161 §9), so the client sends what it showed, and the presence proof (point 3) signs exactly that list. The broker does not re-run the scan, and does not require each step to still be a doctor proposal: the owner may move any of these entries with `entry.move` anyway, so restricting the batch to proposals would add no protection and would make the op depend on the scan's heuristics.
2. **Every step is checked before anything is asked for or moved.** In order: the owner's login (`owner_session`); 1–500 moves; no entry named twice (`malformed_request`); for each step what `entry.move` checks first (not the same node, not the orphan: `malformed_request`; both nodes there: `not_found`; `Admin` on both: `capability_not_held`; neither locked: `node_locked`/`vault_locked`; a vault on disk); each step's `generation` equal to its source's now (`conflict`, with the node and both generations); then a dry run in plan order, each step seeing the earlier ones done: the entry is in its source (`not_found`, so a step whose entry an earlier step moved away is refused), and its name and aliases are free at its destination, counting names an earlier step brings in and the destination's locked-write tray (`entry_exists`). Any refusal here is the request's error and nothing changed; a stale plan costs no finger.
3. **The factors, once for the plan.** A fresh second factor for the vault and for every node the plan names that has its own (`require_fresh_factors_for` on each distinct node), then **one** presence proof for `vault.doctor_apply` (`PRESENCE_EVERY_TIME`; Touch ID reason "Move entries as Tidy up proposed"). The proof's signed digest is over the whole request (`presence::digest(nonce, op, params)`), so a proof made for one plan does not apply another, a proof for `entry.move` does not apply a plan, and the proof is spent by the call. The request takes the exclusive barrier in `server.rs` for the whole plan, as `entry.move` does, so nothing interleaves between the check and the last move.
4. **Each move is `entry.move`'s.** The same crash-safe commit (`state/move_entry.rs`, ADR-158 §5): the same re-seal, stage, single registry write, roll-forward and roll-back on the next load; grants on the moved entry revoked, its history dropped, an approval on the old address discarded. The generation each move echoes is the one the previous step left (a node that is a source twice, or a destination and then a source, carries its own chain). Each applied move is a whole move and is undone the ordinary way, by `entry.move` back; there is no batch undo.
5. **Stop at the first failure, never all-or-nothing.** A failure only the commit can find (a stray file at the destination path, a write error) stops the plan at that move. If no move has been applied yet that is the request's error, and nothing changed. After one or more moves the answer is a report: `{complete: false, applied: [...], stopped: {index, node, entry, to, code, message}, notApplied}`. All-or-nothing was rejected: it would need either a multi-node commit protocol (one registry write binding every manifest the plan touches, with a stage per entry), new crash-recovery code for a rare case, or undoing committed moves (each a re-seal with its own crash window), which is worse than the state it would restore. Each move being atomic, a precise report of which moved is the honest outcome, and the next scan shows what is left.
6. **The answer.** `{complete: true, applied: [...], notApplied: 0}`; each element of `applied` is `entry.move`'s answer (`node` = destination, `entry`, `ref`, `name`, `from`, `generation` = the source's after, `toGeneration`, `grantsRevoked`, `historyDropped`, `cleanupWarning?`) plus its `index` in the plan. Never a value.
7. **Audit.** The generic per-request record of `vault.doctor_apply` (its params are ids and generations, no value). Per move: the destination's `entry.move` item event (`moved from <source>`, as ADR-158, so `entry.history` follows the trail), the source's `entry.move` item event (`moved to <destination> by vault.doctor_apply`, because the plan's generic record names no single node), and a `grant.revoke` item event per revoked grant.
8. **Who.** The owner's login only; MCP never offers it (`FORBIDDEN_OPS`, I-13), for `entry.move`'s reason: it would let an agent carry entries out of its scope. Refusals use existing codes; the 27 stay.
9. **Surfaces.** CLI `credmgr doctor --scan --apply [--yes] [--json]` (no new command; 46 stay): the scan, the plan printed one numbered line per move, then `Apply these N moves? [y/N]` on the terminal; without a terminal it moves nothing unless `--yes` is given; a partial result exits non-zero naming where it stopped. Desktop: bridge `vault_doctor_apply` (94 bridged commands; in `AUDIT_PASSTHROUGH`), `write.applyDoctorPlan`, and Tidy up's **Apply all moves (N)**, which opens a confirm list inside the overlay naming every move (entry, from, to) and what a move does not carry; its Apply sends that list; a refusal before any move is said in the list and nothing moved; afterwards a notice says what moved (a warning when it stopped part-way) and the scan runs again.

**Alternatives rejected.** A `scanId` the broker remembers (the scan writes nothing and keeps nothing by design, ADR-161); re-running the scan inside the apply (seconds of value reading under the exclusive barrier, and a plan the person did not see if the vault changed); asking for presence per move (the point of the op; one proof over the exact list is the same assurance for what is in it); all-or-nothing (point 5); a new error code for a partial result (it is a successful answer that says what happened).

**Not done, and why.** The Apply all moves control is tested against the fixture broker and the shell's bridge tests, not pressed in a built app (`RELEASE_VERIFICATION.md` rows "not pressed — new in ADR-169"). No batch undo plan (ADR-161's "undo plan" phase stays open). Applying `share`, `merge` and `remove_copies` proposals stays later work.

**Tests.** `crates/brokerd/tests/doctor_apply.rs` (6): a scanned plan of three moves (two out of `global`, so the second carries the generation the first left) applies in one request with one proof, every value reads back in its new node, the proof is spent, a move back works, the source and destination records are written, and it survives a restart; a stale generation, the same entry twice, a missing entry, the orphan, an unknown node, the same node, an empty plan and a plan that is not a list are refused and nothing moves; a name an earlier step brings in is `entry_exists` before anything moves; an agent, a dead token and the CLI scope are refused, no proof is `presence_required`, a proof for a different plan or for `entry.move` is `presence_failed`, a locked destination is `node_locked`; a node whose own second factor is not fresh is `two_factor_required` before anything moves; a stray file at the second move's destination stops the plan after the first (`complete: false`, `stopped.index` 1, `code: internal`, the first move stands, the others did not happen) and the same failure at the first move is the request's error. `crates/cli/tests/quick_cmds_cli.rs::doctor_apply_previews_the_plan_asks_first_and_moves_nothing_without_presence`. `src-tauri/tests/bridge_ops.rs` (sweep and `vault_doctor_apply_sends_the_plan_verbatim_…`), `drift_guards.rs` (94 arms), `commands.rs` (94 bridged), `tests/real/drift-guard.test.mjs` and the shim table. `apps/desktop/tests/unit/doctor-apply.test.ts` (8) and `tests/e2e/doctor-apply.spec.ts`. Endpoint matrix rows (the refusals before any finger and the gate order).

## ADR-172 · Entry-level grants: one entry's read and/or reveal, which lists that entry and nothing else, one-way (2026-11-20; closes PHASE8 K-10 (b))

**Context.** PHASE8 K-10 (b) (ADR-078 "Open, recorded"): an entry-level grant could never be used. `entry.list` narrows a node to exactly the entries an entry grant names (`narrow_entries`, `06 §1b`, I-24), but only when the grant's scope holds `list`, and `grant.create` accepts only `read`, `reveal` and `notes`; `entry.reveal`, `entry.get` and `totp.code` resolved only the node-level capability, so an entry grant's `reveal` or `read` was never consulted. `06 §10.2` left two follow-on decisions open: whether `list` becomes grantable for entry grants, and what `direction: mutual` means for one. The failure was closed (a grant that does nothing narrows access); the fix must stay closed toward everything the grant does not name. **Integrator note:** numbered ADR-172 by lane L2 (162–168 were taken, 169 is lane L2's `vault.doctor_apply`); renumber if needed.

**Decision.**

1. **What an entry grant is.** A grant whose `to` is `{kind: "entry", nodeId, entryId}` gives its `from` node (and that node's descendants, as every grant) `read` and/or `reveal` of **that one entry**: `read` is its metadata (`entry.get`), `reveal` its value (`entry.reveal`, the shell's copy) and its one-time code (`totp.code`: a code is reveal-gated like a value). Nothing else: never another entry of the node, never the node itself (its listing, its notes, a node-level read or reveal), never a TOTP seed (`totp.seed` stays node-level and presence-gated), never a write.
2. **It lists its entry, and only it: `list` is implied, never requested.** In `credmgr_core::access::has_matching_grant`, an entry grant whose scope holds `read` or `reveal` also matches `list` for exactly the entry it names (`grant_covers` matches an entry grant only against `Target::Entry` of that entry, so the implied `list` cannot reach a sibling or the node). So `entry.list` and `search` show that one name, through the existing narrowing, and no other name of the node. `grant.create` still refuses `list` in a requested scope (`03 §6`'s type stays `('read'|'reveal'|'notes')[]`): with the implication there is one way to write each grant. The rule lives in `resolve()` (pure, in `crates/core`), so it holds for every caller and for grants created before this change (which could not hold `list` and were inert; they now do what they said).
3. **The broker consults it for one entry's read and reveal.** `entry.reveal`, `entry.get` and `totp.code` resolve the node-level capability first, exactly as before; when that denies for any reason **other than a lock** (R1 comes before every grant and keeps its own approval path for a node-level reader), they ask `resolve()` again at `Target::Entry` for the entry named in the request (`resolve_for_entry` in `ops.rs`). A denial is still reported as the node-level one. Everything after the access decision is unchanged: the security level's approval for an agent (ADR-140), the node's second factor, the vault's "confirm before showing secrets" (ADR-150).
4. **One-way only.** A mutual grant's mirror (`06 §1c`) would let the entry's node read the whole `from` node at the grant's scope: far wider than the one entry the grant names. `grant.create` refuses `direction: "mutual"` with an entry target (`malformed_request`), and `resolve()` ignores the mirror of an entry grant already in a registry (it fails closed).
5. **`notes` is refused for an entry target** (`malformed_request`): notes belong to a node, and a grant that stores a capability nothing can use is a misleading grant. An entry target that is not in its node's manifest is `not_found` at `grant.create` (checked before the presence proof).
6. **What does not change.** `grant.create` stays the owner's: `Admin` on the exposed node, every check above before the proof, then a presence proof (Touch ID) over the exact request; an agent can never hold that proof, and no MCP tool maps to it (`FORBIDDEN_OPS`, I-13). `expiresAt` stays optional, as `03 §6` types it, and an expired grant matches nothing (the implied `list` included). `entry.move` still revokes the grants that name a moved entry (ADR-158). Node-level grants are untouched: a node grant still lists only when its scope says `list` (which `grant.create` does not mint).

**Open questions (conservative choice taken, recorded for the operator).** (a) Whether `grant.create` should also ask for a fresh vault second factor, as `06`'s summary line ("human-only, 2FA-gated, expiring") reads: today the presence proof is the human factor it asks for, and adding the code changes every grant flow in the app, so it is not done here. (b) Whether an entry grant should be required to expire: left optional, as for node grants. (c) Whether an entry-grant holder reading a locked vault should get the approval prompt a node-level reader gets (R1): today it gets an ordinary denial, which is narrower.

**Alternatives rejected.** Making `list` grantable for entry targets (two spellings of one grant, and a `list`-only entry grant that names a secret's existence and nothing else); storing `list` into the scope at creation (grants made before would stay half-usable); answering an entry grant's reveal with the whole node's decision (would widen); keeping the mirror for entry grants (would widen to the whole `from` node).

**Tests.** `crates/core/tests/entry_grants.rs` (5): a reveal grant lists and reveals its entry, never a sibling at any capability, never the node at any capability, nothing once expired; a read grant lists and reads but does not reveal; a notes-only entry grant implies no list; a mutual entry grant mirrors nothing; a node grant still implies no list. `crates/core/tests/isolation_i17.rs`: one generated grant in three is now an entry grant, and the independent re-derivation carries the two rules, so every `Allow` is still justified independently (10,000 cases). `crates/brokerd/tests/grant_ops.rs`: `grant.create` refuses `notes`, `list` and `mutual` for an entry target and an unknown entry, before the proof, and an agent never creates one; an entry reveal grant created with a proof lists exactly its entry, reveals it, refuses the sibling's reveal, the entry's metadata (reveal is not read), another entry's code and the node's notes, and matches nothing once expired or revoked; a read-and-reveal grant on a TOTP entry gives its code and metadata and nothing of the other entry. `crates/brokerd/tests/isolation.rs::i24b_an_entry_reveal_grant_never_reveals_a_sibling_or_lists_the_nodes_other_names` (a reveal-only, mutual entry grant: the list is exactly the granted entry, the sibling's value, metadata and code are refused with no word of it in the refusal, `search` names no sibling, the node's notes are refused, and the mirror opens nothing of `b` to `a`). I-24 still passes unchanged.

### ADR-172 amendment · open questions (a) and (b) closed by the operator (2026-11-20; ADR-174)

**Decided** (ADR-174 items 5 and 6): (a) "Creating a sharing grant needs your authenticator code as well as Touch ID." (b) "Single-entry sharing grants must have an expiry, at most 90 days." (c) is still open.

**(a), built.** `grant.create` (node and entry targets alike) now asks for a fresh vault second factor when one is enrolled (`require_fresh_second_factor`, the arm `maintenance.rotate_root`, `presence.enrol` and the agent-token ops use: `two_factor_required`, scope `global`, until `vault.gate_verify` gives the code), **after** every validation and **before** the presence proof, so a refusal for the code spends no Touch ID. Without a second factor enrolled nothing changes. The CLI's `credmgr grant` says how to give the code on `two_factor_required` (`credmgr gate verify`, then run it again); the app's refusal router already turns `two_factor_required` from an admin action into its notice.

**(b), built.** For an entry target `grant.create` refuses a missing (or `null`) `expiresAt`, and one more than 90 days (7,776,000 s) after the request, as `malformed_request` with a sentence that says what to give; exactly 90 days is accepted. Checked with the other entry-target checks, before the second factor and the proof. Node grants are unchanged (`expiresAt` optional). The CLI gains `--entry <id>` and `--expires-in-days <n>`; a one-entry grant without a chosen expiry is offered 30 days, and the CLI says so. The app's `createGrant` action offers an entry target 30 days when no expiry is passed (the app has no entry-grant screen yet).

**Tests.** `crates/brokerd/tests/grant_ops.rs`: `with_a_second_factor_enrolled_a_grant_needs_a_fresh_code_before_the_proof`, `without_a_second_factor_enrolled_a_grant_needs_the_proof_alone`, `an_entry_grant_must_expire_within_90_days_and_a_node_grant_need_not`; `crates/cli/tests/broker_integration.rs::an_entry_grant_from_the_cli_gets_an_expiry_and_the_broker_caps_it_at_90_days`; `apps/desktop/tests/unit/wp-d.test.ts` (the 30-day offer).

## ADR-173 · A waiting agent request reaches the person without opening the window, and approving in a login needs a presence proof (2026-11-20)

**Context.** An agent's reveal against a locked vault leaves an approval request behind (ADR-042, ADR-088); the Lock screen lists it (ADR-090) and `credmgr approve` decides it. Nothing told the person a request was waiting: they had to open the window. The help entry `nb-native-approval` and `BACKEND_REPORT.md` named the gap, and named a second one: the decision made from a login (the owner's session, used after a node lock, ADR-042) asked for nothing beyond the login, while every other release of a value on this Mac asks for Touch ID once a presence key exists (ADR-098).

**Decision.**

1. **The shell watches** (`apps/desktop/src-tauri/src/approval_notify.rs`). From the run loop's `Ready` event (never from `configure`, so the mock runtime in the integration tests does not start it) a thread asks the broker every 4 seconds for `vault.status` with **no token**: a token-less status is not activity for the idle lock (ADR-090), so the look cannot keep a session from idle-locking. Only when `pendingApprovals` is above zero does it ask `vault.approval_get {}`, which answers any caller while the vault is locked. On an unlocked vault only the owner's login may list requests and this thread has none, so it falls back to the count.
2. **Three things appear, none carrying a value.** (a) A count beside the menu-bar icon and in its tooltip (`set_title`, `set_tooltip`) for as long as a request waits, 99 at most. (b) One macOS user notification per request, coalesced: requests already announced are remembered by id, several new ones between two looks are one notification ("3 agent requests are waiting"), and a later notification replaces an earlier one (a fixed identifier). Not sent while the window is visible and focused: the Lock screen already shows the request. (c) A Dock bounce (`request_user_attention`, informational) alongside the notification.
3. **What the text may say.** The broker does not name the requester (`vault.approval_get` carries no agent label; `cwd` goes to an owner session only), so the text says "an agent". It names the **project label** and nothing else: never a value, never an entry name, never a request id. A project with `privateNames` comes back with a `null` label and is "a private project"; text from the broker is stripped of control characters and cut at 48 characters. When the broker would not list the requests, only a rise in the count is announced, with no project.
4. **Click.** A click on the notification, the menu-bar icon or the Dock icon shows the main window (`tray::show_main`); a locked vault then shows the Lock screen with the request listed (ADR-090). The notification's click handler is a small `NSObject` delegate for `UNUserNotificationCenterDelegate`.
5. **The dependency, decided.** `tauri-plugin-notification` is **not** added: a Tauri plugin adds a capability entry, a JS surface and a broader tree for one call, and ADR-162 declined the dialog plugin on the same ground. The macOS notification is made with `objc2-user-notifications` 0.3 (`default-features = false`, six framework classes), the same objc2 family as the AppKit and Foundation bindings the shell already calls, already present in `Cargo.lock`, licensed Zlib OR Apache-2.0 OR MIT (all on `deny.toml`'s allow list), no network and no HTTP client (`tests/dependency_policy.rs` passes unchanged). It needs a bundled app: a bare binary has no `NSBundle` identifier and is skipped, not crashed. The first notification asks the system for the alert permission; a refusal is the person's choice and is not asked again by the app.
6. **Presence on Approve, enforced where the enforcement is.** `vault.approval_decide` with `approved: true` and **no** `passphrase` (a decision from a login) now needs a presence proof **when a presence key is enrolled**: `require_presence(…, "vault.approval_decide", params, …)`, the same arm `node.policy`, `settings.request_decide` and the others use, so a proof is bound to this op, these exact params (the request id and the verdict), this session and one use. Without a key enrolled nothing changes (the login alone, as ADR-042 and ADR-150 left it). The shell attaches the proof itself when the broker answers `presence_required` (ADR-098), so the page sees no new step. The check runs **before** the confirmation (ADR-150), so a first call that is going to be asked for a proof spends no confirmation. A caller that is not a live login (an agent holding `admin` on the node) can never hold a proof and gets `presence_required`. **Deny is never gated.** `presence_reason` gains `vault.approval_decide`, so the Touch ID dialog reads "Approve an agent's request".
7. **The locked-vault decision is unchanged** (ADR-088): the unlock factors (passphrase, and the authenticator code when a gate is confirmed) authorise it, no session exists to bind a proof to, and a recovery code is still refused. Touch ID cannot stand in for the passphrase there: it would be a second unlock path inside an approval, which ADR-098 decided only `vault.unlock` may have.

**Not done, named.** (a) A notification **action** button ("Approve") is not offered: the decision needs factors the notification cannot carry, so it opens the window. (b) A requester label cannot be shown until the broker records one (an agent identity on the request, not built). (c) The notification has not been seen on a real desktop in this pass: it needs a person, a bundled build and the system permission; the verification rows say "not pressed". (d) Windows and Linux have the count and the bounce only; the notification is macOS.

**Open question for the operator.** Whether a signed, notarised build must declare anything for UserNotifications (none is required for a local notification; ad-hoc signing works). To be answered by the first Developer ID build (ADR-096's release path).

**Tests.** `src/approval_notify.rs` unit tests (9: label cleaning, list parsing with `nameHidden`, one request one notice, several coalesced, the count rule without a list, badge and tooltip); `src-tauri/tests/approval_notify.rs` against a stand-in broker on a real socket (6: no token on any look, the text names the project only and never an entry name, request id or id, a private project, several as one, zero clears, an unlistable broker, no broker); `crates/brokerd/tests/presence.rs` (3: approving needs a proof once a key is enrolled and a proof for a denial does not approve it, deny is never gated, no key enrolled is unchanged); the endpoint matrix and the drift guards unchanged.

## ADR-174 · The operator's decisions of 2026-11-20: thirty open questions answered (2026-11-20)

**Status:** decided by the operator in the rc.2 session on 2026-11-20 (each answer chosen in chat from a recommended option).
Supersedes the "open question" lines it names; each listed ADR keeps its text and gains a pointer here.

**Agents and secrets.** (1) New projects will let agents *use* a secret without *seeing* it (plan 26 §9 Q1; Phase 1 work, not
yet built). (2) Agents may read a project's notes through MCP, never write them (amends ADR-072; tool `credmgr_notes_read`).
(3) No plaintext `.env` export (`credmgr env` is not built); `credmgr run` injection is the path (Phase 1). (4) An exported agent
login works only from its own project folder (closes PHASE8 K-6).

**Vault safety.** (5) `grant.create` needs a fresh authenticator code as well as Touch ID (ADR-172 Q1). (6) Single-entry grants
must expire, at most 90 days (ADR-172 Q2). (7) `maintenance.rotate_root` replaces every project key too (ADR-165 N5-Q1).
(8) The orphan's sealed copies are re-sealed to a new cold key on a re-key (ADR-165 N5-Q2).

**Machine lock (ADR-165 owner questions).** (9) O-1: a backup of a bound vault restores on another Mac with passphrase +
recovery code. (10) O-2: the device key is excluded from Time Machine. (11) O-3: binding refuses a folder in a sync location
(iCloud Drive, CloudStorage providers, Dropbox). (12) O-5: binding needs Touch ID or the authenticator code. O-4 keeps
ADR-165's default.

**Audit, recovery, extras.** (13) No `audit.purge` in 2.x; the full chain is kept. (14) No emergency decrypt for Orphaned
entries (OF-1: not built). (15) A breach check comes later, opt-in, in a separate helper, never in the broker. (16) Remote agent
access waits for a FreeXStudio relay; no third-party tunnel (plan 26 §9 Q2).

**Business.** (17) Tiers: Free + Plus (Solo dropped; prices later; Q3). (18) Two editions: direct download and Mac App Store
(Q4). (19) Family sharing off for in-app purchases (Q5). (20) Counsel reviews the licence and EULA before the first paid tier
(Q7). (21) Paddle for direct and Windows sales (Q8). (22) Who hosts a sync relay is decided when sync is built (Q6).

**Tags and merge.** (23) Agents see tags in `entry.list` rows (ADR-167 a). (24) Tags filter exactly; no fuzzy match (ADR-167 b).
(25) `merge.auto*` joins identical values only (ADR-168 a). (26) A merge copies no fields (ADR-168 c).

**Small rules.** (27) A dismissed merge suggestion does not follow a moved entry (ADR-168 b). (28) An entry-grant holder gets a
plain refusal while the vault is locked, not an approval prompt (ADR-172 Q3). (29) Confirm-before-showing stays on reveals and
copies (K-24 scope kept). (30) CredMgr's own self-hosted runner stays the CI while hosted Actions are billing-locked, restricted to the
private repository (K-15).

**Built on 2026-11-20:** (2), (4), (5)–(12), (23), on branches `feat/adr174-d1` (5–8), `feat/adr174-d2` (9–12) and
`feat/adr174-d3` (2, 4, 23); each lane amends the ADR it closes. Already true of the code: (13), (14), (24)–(30). Recorded for
later phases: (1), (3), (15)–(22).
