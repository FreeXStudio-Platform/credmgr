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
6. **Not taken:** the helmet CSS line that darkens input borders (`--faint` to `--mute`): an accessibility contrast change that is the owner's call, left as it was. The design's Security-level row and its `entryWarn` banner (ours exists in another form) were not needed.

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
