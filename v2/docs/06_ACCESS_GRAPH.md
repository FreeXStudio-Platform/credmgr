---
id: V2-006
classification: public
title: The access graph
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-19
---

<!-- artifact-hardened: NEEDS RE-HARDENING — rewritten to ultimate-destination state on
     2026-08-18 (Session 21). Every rule, capability, error field and worked trace below was
     re-derived from `crates/core/src/access.rs`, `crates/brokerd/src/{scope,ops,protocol}.rs`
     and the tests named in §12, and eleven claims were corrected (the rule table omitted the
     orphan-as-subject guard and mutual grants; §3 still listed a `write` capability that no
     longer exists; §5's example error carried sentences the broker never emits; §6 described a
     `grant.create` that refuses on every transport as though it ran). The previous stamp
     (`Approved With Known Risks @ 6ee1e5f`) predated those corrections and named a body this one
     no longer is.

     CORRECTED AGAIN 2026-08-18 (Session 21, verification-backlog pass, same day). Six further
     claims fixed against live source: §10.3 undercounted the `presence_required` return sites as
     four when there are five (`audit.get`, `totp.seed`, `node.reparent`, `grant.create`,
     `maintenance.doctor --rebuild-registry`) and placed `PresenceProof` inside the Tauri bridge's
     command surface — it is defined in `crates/keystore`'s `PlatformKeystore` trait, and
     the bridge carries no `PresenceProof` at all, only the literal string `"presence_required"`;
     §3's `reveal` row marked `totp.seed` **built** with no carve-out though it refuses
     unconditionally for want of presence, inconsistent with the `admin` row's own carve-out two
     lines below; §3's `admin` row counted sixteen op arms where there are fifteen (sixteen
     `Capability::Admin` call sites, but `maintenance.doctor` checks it twice); and §1/§1a described
     the desktop shell as not existing, when its Tauri bridge is real, built and tested (ADR-057,
     eight bridged commands, session token held Rust-side) — only the UI screens and the
     node-lock/unlock bridge commands are missing, not the application. Four wrong section
     citations were also fixed: three citations of `05_THREAT_MODEL.md §7` (that section is
     "Explicitly out of scope"; the anomaly/detection content this document cites is `§8`), and one
     citation of `13_TEST_PLAN.md §3` (that section is "Property tests (core)"; the isolation
     suite's coverage table is `§4.1`). One flagged claim — the §1c ancestor-widening description —
     was checked against `crates/core/src/access.rs:119-133` and found already correct (widens
     toward descendants, not ancestors); left unchanged. Assigning `Approved` is the operator's
     call after their own review, not this session's to self-award.

     CORRECTED AGAIN 2026-08-19 (Session 21, verification-backlog ROUND 2). One further claim
     fixed against live source: §10.3 named the crate that will define `PresenceProof` as "the
     platform-keystore crate" — a crate of that name (`platform-keystore` or `platform_keystore`)
     does not exist anywhere in the v2 Cargo workspace (`find` under `v2/` for either spelling
     returns nothing; `v2/Cargo.toml`'s workspace member list has no such path). `PresenceProof`
     and the `PlatformKeystore` trait it belongs to are both defined in `crates/keystore`
     (package `credmgr-keystore`, lib `credmgr_keystore`) — confirmed by
     `grep -rn "PresenceProof" v2/crates`, which finds it only in
     `crates/keystore/src/lib.rs` and `crates/keystore/src/software.rs`. The
     CORRECTED-AGAIN-2026-08-18 paragraph above repeated the same wrong name in its own prose and
     is corrected in place rather than left to disagree with this one. Every other crate reference
     in this document already used the real, code-formatted path (`crates/core`, `crates/brokerd`,
     etc.); §10.3 now does too. No other finding was raised against this document in round 2.
     Assigning `Approved` remains the operator's call, not this session's to self-award.
     Updated 2026-09-24 for ADR-062…066 (a real login evaluated as the target node, settable
     workdirs, the bridge at 42 ops). Updated 2026-09-24 for ADR-071…072 (`node.update` and
     `node.policy` built with presence-gated widening still refused, §10.1; `notes.read`/
     `notes.write` built behind the `notes` capability, §3; the bridge at 47 ops). Updated 2026-10-02 for
     ADR-077 (`node_locked` is the wire answer to a write on an individually locked node, §1a; an
     agent's `entry.list` carries no `entries` metadata, §3). Updated 2026-10-03 for ADR-078/079 (`entry.get`
     is built and gated on `read`, the `field.*` operations on `update`, §3; the node lock and grant dialogs
     are wired in the desktop app, §1a, status; sealing is durable and the orphan cold key exists, §9; the
     bridge at 53 ops; I-27…I-29, §12). -->
# The access graph

`CredMgr V2` · the rules that decide every read, and the one function that applies them · `2026-08-18`

> **Status.** The resolution function and rules R0–R8 are **built** and are the second link in
> the security chain (`00_README_START_HERE.md §6`): `crates/core/src/access.rs::resolve` is pure,
> takes lock state and the clock as parameters, and is the only place any rule is expressed. It is
> covered by the worked matrix in `crates/core/tests/access_matrix.rs`, by P-9/P-10 in
> `crates/core/tests/properties.rs`, by I-17's independent rule re-derivation over random 30-node
> graphs, and by the isolation tests named in §12. What is **partial** is the
> machinery around it: grants can be listed and revoked but **`grant.create` refuses on every
> transport that exists** (`presence_required`), node policies can be changed by `node.policy`
> (ADR-071) only in the tightening direction — a widening patch refuses for want of presence;
> `requireTwoFactor` and `privateNames` are enforced since 2026-10-24 (ADR-085, ADR-083; against the vault gate's
> one scope — a per-node gate secret is still unbuilt) — the
> native presence origin is unwired, and the
> cross-node-denial counter trips without emitting anything. The desktop app's grant surfaces are
> **wired**: Settings → Grants lists what `grant.list` returns, revokes with `grant.revoke`, and its
> "New grant" dialog sends `grant.create`, which the broker refuses with `presence_required` (the app says
> so and changes nothing) — a human still cannot create a grant on any surface, because nothing can attest
> presence (`19_FRONTEND_DELIVERY_SCOPE.md`).
> Each section below carries its own status and its own evidence; §10 collects the target design
> for the parts that exist nowhere yet.

---

## 1. The rules, in precedence order — **built**

One function decides every read in the system. It lives in `crates/core/src/access.rs`, performs
no I/O, reads no clock and no environment, and returns which rule decided as part of the decision.
Every client — the CLI, the MCP server, and the desktop shell's Tauri bridge (ADR-057, ADR-062;
all 53 of the broker's operations are reachable through it) — reaches it through the broker; none
of them re-implements a rule.

```rust
pub fn resolve(
    ctx: &AccessContext,      // registry + vault_locked + locked_nodes + now
    subject: &Scope,          // node_id, origin, presence_attested
    target: &Target,          // Node(id) | Entry { node_id, entry_id }
    capability: Capability,
) -> Decision                 // Allow(Rule) | Deny(Rule)
```

The shape is the point. **Lock state and "now" are parameters, not ambient facts**, which is what
makes the whole rule set testable by a pure fuzz harness: I-17 can generate a random graph, a
random subject, a random clock and a random lock set, and re-derive from `06`'s own prose whether
the rule `resolve` named actually holds — something it could not do if `resolve` reached for a
`SystemTime` or a mutex of its own.

Evaluated top to bottom; the first rule that matches decides. **Default is deny.**

| # | Rule | Effect |
|---|---|---|
| **pre** | The **subject** is the orphan node | **DENY**, reported as R8, before R0 is considered. Orphan is a place data goes, never a caller. The broker is expected never to mint such a scope; this is the pure-function backstop for that expectation. |
| **R0** | Target node is `orphan` | **DENY** for every subject and every transport, except a subject whose `origin` is `native` **and** which carries a live presence attestation. No grant, policy, or token can override it. |
| **R1** | Target is locked — **vault locked**, or **node-level lock** (§1a) | **DENY** `reveal` and `update` only; `list`/`read` still resolve through the later rules. A `reveal` that would otherwise have been allowed returns `approval_pending` rather than a flat denial (§5, `07_TWO_FACTOR.md §5a`). |
| **R2** | Subject node **is** the target node | **ALLOW** |
| **R3** | Target is `global` | **ALLOW** — global is readable by every node, by definition |
| **R4** | Target is a **strict ancestor** of the subject | **ALLOW** — upward inheritance |
| **R5** | Target is a **descendant** of the subject **and** the subject's own policy sets `descendantRead: true` | **ALLOW**, else fall through |
| **R6** | Subject and target are **siblings sharing a parent** whose `policy.siblingVisibility === 'shared'`, **and both are at depth 2** | **ALLOW** |
| **R7** | An active, unexpired **grant** exists whose `from` is the subject (or a strict ancestor of the subject), whose `to` covers the target, and whose `scope` includes the requested capability | **ALLOW**, narrowed per §1b. A grant marked `direction: 'mutual'` also matches with its endpoints swapped (§1c). |
| **R8** | — | **DENY** |

Three clarifications that matter and are easy to get wrong:

- **R4 is strict and transitive.** Sub-node X reads its parent A *and* Global. It does not read
  A's siblings. `Registry::is_strict_ancestor` walks the parent chain and never counts the node
  itself.
- **R5 consults the subject, not the chain.** The rule is one boolean on the node doing the
  reading — "may I see into my own subtree" — not a walk of the target's ancestry. An earlier
  wording of this section said both, which cannot both be true; the code has only ever done the
  former.
- **R6 never applies at depth 1.** Projects A, B, C, D never see each other, whatever any policy
  says, because `are_shared_depth2_siblings` rejects the pair before it looks at the parent's
  policy. `siblingVisibility` on the *global* node is additionally fixed at `'isolated'` at
  construction — the top-level partition is the product.

**Evidence.** `crates/core/src/access.rs` (the rule ladder, one branch per row);
`crates/core/tests/access_matrix.rs::worked_example_matrix_matches_every_cell` (§2's table, cell by
cell); `crates/core/tests/isolation_i17.rs` (I-17 — for every `Allow(rule)` over a random 30-node
graph, an independent re-derivation of whether that rule's condition actually holds, written from
this section's prose rather than by calling back into `access.rs`);
`crates/core/tests/properties.rs::p9_resolve_allow_always_has_a_named_rule` and
`::p10_resolve_is_monotone_in_grants`.

<!-- figure:access-rule-ladder -->

*Every rung, condition and exit above is transcribed directly from `resolve()`'s literal branch
order (`crates/core/src/access.rs:142-219`) — the diamond order in the figure is the ladder.*

### 1a · Node-level lock — **built** (the lock itself), **planned** (the way a human sets it)

A node can be locked **individually while the vault stays unlocked**. Its private key leaves the
broker's hot set; `reveal` and `update` fail with R1; `list` and `read` continue from the plaintext
manifest. Unlocking it costs the node's gate factor.

The intended user is the wallet node: the vault stays open all day for ordinary work, and the node
holding seed phrases is shut the moment it is not in use.

**Built.** `vault.node_lock` / `vault.node_unlock` are dispatched ops, each gated on
`Capability::Admin` both as a token ceiling and through `resolve` against the target node.
`resolve` reads the locked set through `AccessContext::locked_nodes`, so a node-level lock and a
vault-wide lock produce the identical R1 denial. The per-node idle timer is real: a node whose
policy carries `lockAfterSeconds` is swept and locked on its own clock, independently of the vault
(`crates/brokerd/src/state.rs`, exercised by
`crates/brokerd/tests/phase3_exit_gate.rs::a_nodes_own_lock_after_seconds_locks_only_that_node_not_the_vault`).

**Planned.** The desktop application itself is not the missing part — `apps/desktop/src-tauri`
builds, registers a command for every broker op (`vault_node_lock`/`vault_node_unlock` among them
since ADR-062), and holds the ADR-057 session token Rust-side so the webview never sees it; locking
one node does not end that login (ADR-062's `VAULT_STATE_OPS` fix). The node
context menu's `Lock now` / `Unlock node` and the lock glyph that renders the state
(`09_UI_UX_SPEC.md §3`) are wired to `vault.node_lock` / `vault.node_unlock` (`apps/desktop/`, ADR-075). Setting or
clearing `lockAfterSeconds` is `node.policy`'s job since 2026-09-24 (ADR-071, §10.1); it had no
operation behind it before.

### 1b · An entry grant is not a directory listing — **built**

When R7 matches on a grant whose `to.kind === 'entry'`, the allow is narrowed to **exactly the
granted entries**. In particular `list` against that node returns only those entries — never the
node's full inventory. Otherwise "B may read one API key from A" would quietly leak A's complete
credential index, which is most of the reconnaissance value in the first place.

The mechanism is not a special case inside `resolve`. `resolve` denies the node-level request as
usual, and the broker then re-runs the same function once per manifest entry with
`Target::Entry { node_id, entry_id }`; only entries that come back `Allow` are returned
(`narrow_entries` in `crates/brokerd/src/ops.rs`). If none does, the caller gets the ordinary
denial of §5 rather than an empty list — empty means "nothing there", denied means "not yours".

**One honest seam.** The narrowing needs the grant's `scope` to contain `list`, and
`grant.create` refuses any scope outside `read`/`reveal`/`notes` (`03_DATA_MODEL.md §6` types it
that way, and the op enforces it). So the exact grant shape I-24 proves the narrowing against —
`scope: [list, read]` on an entry target — cannot currently be minted through the built operation;
the test injects it into the registry directly. The narrowing code is correct and tested; what is
missing is a way for an operator to produce the grant it narrows. Resolving that is §10.2.

**Evidence.** `crates/brokerd/tests/isolation.rs::i24_entry_level_grant_narrows_list_to_exactly_the_granted_entry`
— node `a` holds two entries, `b` holds an entry-scoped grant to one of them, and `entry.list`
against `a` returns exactly that one id.

### 1c · Mutual grants — **built**, and previously undocumented here

`03_DATA_MODEL.md §6` types a grant's `direction` as `'one-way' | 'mutual'` but does not say what
`mutual` means at resolution time. It means what the graph implies: R7 additionally matches as if
a mirror grant existed with `from` and `to` swapped, so a mutual edge between X and B lets B read
X on the same scope and expiry that lets X read B. The widening applies on both sides — but it
widens toward **descendants**, not ancestors: `has_matching_grant` matches when
`registry.is_strict_ancestor(&grant.from, subject_node)`, i.e. when `grant.from` is an ancestor of
the subject, so the subject reached is a *descendant* of the endpoint. A strict ancestor of either
endpoint gets nothing. The mutual branch is the same shape with `to_node`.

This is enforcement, not decoration: a mutual grant is one row in the registry and one dashed line
on the graph, and revoking it closes both directions at once. It is recorded here because the
resolution semantics lived only in a doc comment in `crates/core/src/registry.rs` and in the
`Direction::Mutual` branch of `has_matching_grant`, and a rule that exists only in code is a rule
the next reviewer will not know to check.

---

## 2. The brief's example, resolved exactly — **built**

Given: Global; projects **A, B, C, D** at depth 1; sub-nodes **X, Y** under A at depth 2.
Default policies. Plus one human-created grant **X → B (read)**.

```
                        ┌────────┐
                        │ GLOBAL │
                        └───┬────┘
            ┌───────┬───────┼───────┬───────┐
          ┌─┴─┐   ┌─┴─┐   ┌─┴─┐   ┌─┴─┐
          │ A │   │ B │   │ C │   │ D │
          └─┬─┘   └─┬─┘   └───┘   └───┘
        ┌───┴───┐   ╎
      ┌─┴─┐  ┌──┴┐  ╎  ← dashed: the human grant X → B
      │ X │──│ Y │  ╎
      └─┬─┘  └───┘  ╎
        ╎ ╎ ╎ ╎ ╎ ╎ ╎
```

Reader (row) → can read (column)?

| ↓ reads → | Global | A | B | C | D | X | Y | Orphan |
|---|---|---|---|---|---|---|---|---|
| **Global** | ✅ self | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **A** | ✅ R3 | ✅ self | ❌ | ❌ | ❌ | ❌ *(R5, off)* | ❌ *(R5, off)* | ❌ |
| **B** | ✅ R3 | ❌ | ✅ self | ❌ | ❌ | ❌ | ❌ | ❌ |
| **C** | ✅ R3 | ❌ | ❌ | ✅ self | ❌ | ❌ | ❌ | ❌ |
| **D** | ✅ R3 | ❌ | ❌ | ❌ | ✅ self | ❌ | ❌ | ❌ |
| **X** | ✅ R3 | ✅ R4 | **✅ R7 grant** | ❌ | ❌ | ✅ self | ✅ R6 sibling | ❌ |
| **Y** | ✅ R3 | ✅ R4 | ❌ *(the grant is X's, not Y's)* | ❌ | ❌ | ✅ R6 | ✅ self | ❌ |
| **Orphan** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ (not a subject) |

This table is not illustrative. It is transcribed into `crates/core/tests/access_matrix.rs` as a
literal boolean grid and asserted cell by cell against `resolve`, so a rule change that would alter
any cell fails the build rather than quietly re-drawing the diagram.

Note the row that proves the model works: **Y cannot reach B**, even though Y's sibling X can, and
even though Y and X share everything else. Grants attach to a node, not to a family. If Y needs B,
that is a second grant, drawn deliberately.

Note also **A cannot read X or Y** by default (decision D-01, `01_CONCEPT.md §5`). If "Linux"
holds dev/staging/prod as sub-nodes, working in the parent does not hand you prod.

The Orphan row is denied by the subject-side guard in §1's rule table — including its Global cell,
which R3 would otherwise allow. That cell is the reason the guard exists as code and not merely as
an expectation about what scopes the broker mints.

---

## 3. Capabilities — **partial**

A decision is per-capability, not a single boolean. Seven capabilities exist as a Rust enum in
`crates/core/src/registry.rs`; `resolve` treats all seven identically (the rules are about
reachability, the capability is about what reaching buys you), and the broker checks each op
against the one it needs.

| Capability | Grants | Status of the ops behind it |
|---|---|---|
| `list` | entry names, refs, types, counts — no values, no field labels | **built** — gates `entry.list`, `search`, `node.list`, `graph.snapshot`, `audit.tail` |
| `read` | full metadata incl. field **labels**, still no values | **built** — gates `entry.get` (ADR-078: field ids, labels, types, masking and the entry's metadata, never a value; needs the node unlocked, so R1 → `vault_locked` / `node_locked` with no approval path) and `vault.pending_list`. `notes.read` gates on `notes`, not `read` (below) |
| `reveal` | the actual secret values | **built** — gates `entry.reveal`, `totp.code`, `totp.seed`, the last of which then refuses unconditionally for want of presence, same carve-out as three of the `admin` row's ops below (§4, §10.3) |
| `create` | add a **new** entry (a name not already in the node) — **does not imply read** | **built** — gates `entry.create`, which works while locked and lands in the pending tray |
| `update` | modify an existing entry or field | **built** — gates `entry.update`, `entry.rotate`, `entry.remove`, `entry.undo`, `entry.restore` and, since ADR-078, `field.add`, `field.update`, `field.remove`, `field.reorder`; **requires the vault unlocked**, via R1 |
| `notes` | the node's markdown | **built** — gates `notes.read` and `notes.write` (ADR-072), resolved against the node; the note is sealed under the node key and bound to its manifest digest (`03_DATA_MODEL.md §4`). Evidence: `durable_vault.rs::a_note_is_sealed_capability_gated_digest_bound_and_survives_a_restart` |
| `admin` | node lifecycle, grants, seal/restore, reparent | **built** — gates eighteen distinct op arms (eighteen `scope.holds(Capability::Admin)` call sites — `maintenance.doctor` checks it twice, once per internal path, and `node.update`/`node.policy` share one in `human_admin_on`, which also refuses `Origin::Agent`; recounted 2026-09-24 for ADR-071 — fifteen arms and sixteen sites before `node.set_workdirs`, ADR-066); three of the eighteen (`audit.get`, `node.reparent`, `grant.create`) then refuse unconditionally for want of presence (§4, §6, §6a). A fourth, `maintenance.doctor --rebuild-registry`, refuses the same way but only on that one path — its ordinary path does not require presence. Together with `totp.seed` above, those are five of the broker's six `presence_required` return sites (§10.3); the sixth is `node.policy`'s refusal of a patch that widens reach (ADR-071, §10.1). |

`notes` deliberately does **not** ride along with `read`. Context is separately sensitive
(`01_CONCEPT.md §3`), so it is separately requested.

**`write` was split into `create` and `update`.** A single write capability, combined with
asymmetric node keys, would let any holder **overwrite an existing credential with one they
control** — without ever reading it, and while the vault is locked. That is credential
substitution, and it is a worse outcome than an unauthorised read. `create` is therefore permitted
while locked (into a review tray) and `update` requires the vault open, on the principle that a
legitimate update implies you could have read what you are replacing. See `04_CRYPTO_AND_KEYS.md §3`.
There is no `write` capability anywhere in the codebase; earlier text in this document and in §7's
traces still named one, and that is corrected here.

**What a caller can hold, and where it comes from.** Two shapes exist today, and only two:

- A **cwd-derived scope** (no token) gets capabilities from the target node's `agentAccess`
  policy: `read-write` yields `list, read, reveal, create, update`; `read-only` yields
  `list, read, reveal`; `none` yields nothing. **`notes` and `admin` are never in a cwd-derived
  scope**, whatever the policy says — both require an explicit grant or a real login.
- A **session token**, minted only by a successful `vault.unlock` or `vault.gate_verify`
  (ADR-056), carries every capability at `node_id: global`, `origin: human-ui`. This is the only
  non-fixture path to `admin` in the entire system, and it is why R3's capability-unqualified
  ALLOW is inert in practice: an `admin`-holding subject scoped to global resolves `admin` against
  global through R2, never R3. If a future session ever mints an `admin` token scoped to a
  non-global node, R3 is the rule that must be revisited first (ADR-056 records this explicitly).

**A real login is evaluated as the target node — `built` since 2026-09-24 (ADR-065).** A token
still minted global-scoped would, under R8, let its owner list, read or write nothing but
`global` — ADR-047's and ADR-056's named gap. So a **real login session** — a token minted by
`vault.unlock`/`vault.gate_verify` and still registered in the broker's session set — is evaluated
**as the target node itself** (`crates/brokerd/src/ops.rs::subject_for`), for every target except
Orphaned. `resolve()`'s precedence does the rest: R0 (Orphaned: native origin and live presence
only) and R1 (a locked vault or node blocks `reveal`/`update`) sit before R2, so both still bind the
owner exactly as they bind anyone, and because subject and target are the same node, `admin`
still resolves through R2, never R3. Nothing else widens: an agent's scope, a cwd-derived scope, and
any scope that merely *claims* `origin: human-ui` without a registered token resolve exactly as
before, and `crates/core/src/access.rs` is unchanged — this is a broker-side choice of subject, not
a new rule. The session ends at `lock()` (explicit, idle, sleep, restart) and, on its own clock,
when unused for the vault idle timeout, even while agent traffic keeps the vault unlocked. The
known risk it creates — a login exported into a shell an agent also runs in hands that agent every
project — is K-6 (`PHASE8_AUDIT_REPORT.md §4`). Test:
`crates/brokerd/tests/durable_vault.rs::the_owner_session_reaches_every_project_but_an_agent_and_a_fixture_claim_do_not`.

---

## 4. Subject scope — where a caller's node comes from — **partial**

```ts
type Scope = {
  nodeId: string;                    // the caller's home node
  capabilities: Capability[];        // ceiling, cannot be raised at runtime
  origin: 'human-ui' | 'cli' | 'agent' | 'native';
  tokenId: string | null;
  boundWorkdir: string | null;       // recorded at issue; compared at use
};
```

The ceiling and `resolve` are checked **in addition to each other, never instead of each other**.
A token that does not carry a capability is refused with `capability_not_held` before `resolve`
runs at all — which is why that error never claims a rule number.

Resolution order when a client connects (`crates/brokerd/src/scope.rs::resolve_scope`):

1. **Explicit token** → its `nodeId` wins, always. **built** (A real login's token is then
   evaluated as each target node rather than as `global` — §3, ADR-065.) A token the broker does
   **not** hold — idled out, revoked at lock, or never issued — is refused as `session_expired`
   rather than falling through to step 2, except on the ops that report or re-establish a session,
   or lock (ADR-068; `server.rs::handle_request_at`). Until 2026-09-24 it fell through, silently
   demoting its holder.
2. **No token, cwd matches a `workdirs[]` entry** → that node, with `agentAccess`-derived
   capabilities, `origin: 'agent'`. Longest match wins, so a sub-node's own registered directory
   beats an ancestor's, and a process launched anywhere beneath a registered directory resolves to
   it. This is how an MCP server started inside a project directory just works. **built** —
   and since 2026-09-24 reachable in a real vault: `node.create`'s optional `workdirs` and
   `node.set_workdirs` bind directories, stored canonical, human-only (ADR-066,
   `03_DATA_MODEL.md §1`). Before that nothing could set `workdirs`, so no vault `credmgr init`
   made could scope an agent to a project.
3. **No token, cwd unknown** → scope `global`, capability `list` only. A stranger sees that the
   vault exists and nothing else. **built**
4. **Native app with presence attestation** → `origin: 'native'`, the only origin allowed to reach
   the orphan node. **planned** — and this is the single most consequential unbuilt thing in this
   document. `resolve_scope` has no fourth branch, and every call site in the broker constructs
   its subject with `presence_attested: false` hard-coded. R0's allow branch and every op that
   ends in `presence_required` are therefore unreachable end to end on every transport that
   exists. The target design is in §10.3.

If the presenting process's cwd disagrees with the token's `boundWorkdir`, the request still
proceeds under the token — the token is the authority — but the mismatch is recorded to the audit
log as `anomaly.token_workdir_mismatch` before the operation runs (`05_THREAT_MODEL.md §8`).
**built**, and proven by
`crates/brokerd/tests/isolation.rs::i12_token_workdir_mismatch_proceeds_and_writes_an_anomaly_to_the_audit_log`.

---

## 5. Denials must be legible — **built**

A denial that looks like "no results" teaches an agent to retry, rephrase, and eventually find a
way through. V2 denials are explicit and self-explaining. This is the exact shape the broker emits
today, field for field:

```json
{
  "id": "req-7",
  "ok": false,
  "error": "node_access_denied",
  "subject": "northwind",
  "target": "acme",
  "capability": "reveal",
  "rule": "R8",
  "message": "Node 'acme' is not readable from node 'northwind'.",
  "remedy": "A human can create a grant: credmgr grant northwind --to acme --scope read --reason \"...\""
}
```

The `remedy` field matters: it tells the agent the correct next action is *ask the human*, not
*try harder*. An agent that reports "I need a grant for X because Y" is the behaviour this whole
design is trying to produce. The command it names is the real CLI shape
(`crates/cli/src/main.rs::cmd_grant`), so a human who is handed the message can run it verbatim.

`message` is enriched in exactly one case: when the denial is R8 **and** a grant exists that would
have allowed the request but has expired, the message says so and names the expiry, rather than
letting a lapsed grant look identical to one that never existed. Nothing else is added — earlier
text in this section showed a `message` carrying "Nodes at depth 1 are isolated by design." and a
`remedy` ending "Requires 2FA and cannot be created by an agent."; the broker emits neither
sentence, and this document no longer claims it does.

**Never** silently return an empty list where a denial occurred. Empty means "nothing there";
denied means "not yours". Conflating them is how boundaries erode. The one place the two are
deliberately made indistinguishable is `search`: a term that matches only inside an unreachable
node and a term that matches nowhere both return `{"results": []}`, because a *count* would
otherwise be the leak (I-3).

**Evidence.** `crates/brokerd/src/ops.rs::access_denied_error` builds the error;
`crates/brokerd/src/protocol.rs` serialises exactly the seven fields above;
`crates/brokerd/tests/isolation.rs::i1_cross_node_reveal_is_denied_with_no_leak` asserts the denial
carries no fragment of the target's contents; `::i3_search_only_matches_in_out_of_scope_node_returns_zero_results_same_as_no_match`
asserts the search equivalence; `::i7_expired_grant_is_denied_and_reported_as_expired` asserts the
expired-grant enrichment.

---

## 6. Grant lifecycle — **partial**

```
   propose ──► confirm ──► active ──► (expire | revoke) ──► historical
      │           │           │
   drag on     dialog:     dashed
   the graph   scope +     edge on
   or CLI      reason +    the graph
               expiry +
               2FA + presence
```

**What is built.** `grant.list` and `grant.revoke` are real, executing operations. Both are gated
on `Capability::Admin` resolved against the grant's `to` endpoint — the node whose confidentiality
boundary the grant widens — because administering B's exposure is B's administrator's call, not
X's (ADR-050). Revocation takes effect on the very next request, with no re-encryption, because
grants are soft (`04_CRYPTO_AND_KEYS.md §4`). Expiry is honoured inside `resolve` itself: a grant
whose `expiresAt` has passed simply stops matching R7, with no sweep, timer or background job
involved. `reason` is validated at eight characters minimum, and a grant naming `orphan` at either
endpoint is rejected outright.

**What is not built, and must not be read as though it were.** `grant.create` validates
everything it can — the endpoints, the reason length, that the requested scope contains only
`read`, `reveal` or `notes`, that the caller holds `admin` and that `resolve` allows `admin`
against the target — and then returns `presence_required` unconditionally. **No grant has ever
been created through a shipped surface.** Every grant in every test is injected into the registry
directly. The refusal is correct rather than incomplete: creating a grant is the one operation in
this system that widens what existing data is reachable, `07_TWO_FACTOR.md §2` names it as
requiring presence, and no transport can supply presence yet (§4, step 4). But a reader who takes
this section's diagram as a description of something that runs would be wrong, and this paragraph
exists so they cannot be.

**Target design for the parts that are `planned`.** When the desktop shell exists:

- **Proposal will be cheap, creation will not.** Dragging X onto B will open a pre-filled dialog.
  The dialog will require a capability set, a reason of at least eight characters, an expiry
  choice, a TOTP code, and a biometric prompt — the same four inputs `grant.create` already
  validates, plus the presence attestation it currently waits for.
- **Default expiry will be 30 days.** "Never" will be offered and will render with a warning chip.
- **Revocation will be one click**, and will remain reachable in both Pro and Lite: creating a
  grant is a lever and is Pro-only; removing one is safety and is always reachable.
- **A stale-grant sweep** will surface any grant unused for 30 days in `credmgr audit` and as a
  Pro-mode banner. `lastUsedAt` is typed for it in `03_DATA_MODEL.md §6` and is not yet written by
  anything. Unused grants are the quiet way a partitioned vault becomes a flat one.
- **Grants will survive rename** (they reference immutable ids) and **will not survive seal** — if
  either endpoint is sealed the grant will be revoked and recorded as such.

<!-- figure:grant-lifecycle-built-vs-planned -->

*`historical` is deliberately absent from the figure above, though it appears in the ASCII sketch
earlier in this section: no code ever moves a grant into a distinct "historical" bucket — a
revoked grant is deleted outright (`state.revoke_grant`), and an expired one simply sits inert,
unswept, forever. The figure names only the two terminal states the code actually produces.*

### 6a · Re-parenting is a scope-widening operation — **partial**

Moving a node to a different parent changes its ancestor set, and R4 therefore changes what it can
read — the same effect as creating a grant, achieved through what looks like an ordinary edit.
Treated as a rename-class change, it would be the cheapest way to widen access in the whole system.

Re-parenting therefore carries the **full grant gate**: gate 2FA, biometric presence, a mandatory
reason, and an audit record.

**Built:** `node.reparent` refuses `global` and `orphan` as targets, enforces the eight-character
reason, requires `Capability::Admin` as a ceiling, and resolves `admin` against the node being
moved — then returns `presence_required`. Nothing about the arm needs to change when presence
becomes available; the refusal is the last statement, not a stub in place of the checks.
`crates/brokerd/tests/isolation.rs::i23_reparent_refuses_on_every_phase3_surface_admin_included`
asserts the refusal holds even for a caller holding `admin`.

**Planned:** the confirmation dialog, which will enumerate by name exactly which nodes become
newly readable and which become unreadable before the operator commits:

```
  Move "staging" from "linux" to "acme"?

  staging will GAIN read access to:   acme
  staging will LOSE read access to:   linux
  Grants affected:                    none

  Reason [                                        ]   2FA [ ______ ]
```

Computing those two lists needs no new mechanism — it is `resolve` run twice, once against the
current registry and once against a scratch clone with the new parent, differenced. That is the
same scratch-clone-then-validate pattern `node.create` already uses to check depth invariants
before touching the real registry.

---

## 7. Worked traces — **partial**

Each trace names its own status, because they do not share one: (b) and (e) run end to end today,
while (a), (c) and (d) each have a designed half that no transport can reach.

**(a) Agent in a project directory requests that project's database password.** — **built**
Scope from cwd → `northwind`, capabilities `[list, read, reveal, create, update]` from
`agentAccess: read-write`. Target node = `northwind`. R2 matches → ALLOW. The value is decrypted
under `northwind`'s hot node key and returned. Audit: one allow record.
*Built since 2026-10-24 (ADR-085):* the node's `requireTwoFactor` policy **is consulted on reveal**. With a
confirmed vault gate, a reader that is not the owner's own login gets `two_factor_required` unless a
fresh gate verification (the owner's login, or a step-up with `vault.gate_verify` mid-session) is inside the
five-minute elevation window. The factor is still the vault gate's — a per-node gate secret is `planned`
(§10.4) — and `crates/brokerd/tests/phase5_gate.rs`'s own scope note about the earlier state is history.

**(b) The same agent requests a credential belonging to a different project.** — **built**
Target node = `acme`. Subject is not orphan · R0 no · R1 no · R2 no · R3 no · R4 no (not an
ancestor) · R5 no · R6 no (depth 1) · R7 no grant → **R8 DENY**. Response exactly as in §5. Audit:
a deny record carrying the requesting process's cwd.
*Partial:* the fifth such cross-node denial from the same uid inside ten minutes does trip the
counter — `crates/brokerd/src/rate_limit.rs` returns `true` on exactly that request, and
`crates/brokerd/tests/isolation.rs::i16_five_cross_node_denials_in_ten_minutes_trip_the_anomaly`
proves it — but `crates/brokerd/src/server.rs` discards that return value. **Nothing is emitted.**
There is no banner, no notification, and no audit record distinct from the individual denials. The
detector is built; the alarm bell is not wired to it (§10.5).

**(c) Agent in sub-node X requests an entry in A.** — **built**
R4 matches (A is a strict ancestor) → ALLOW. Proven by
`::i4_subnode_reads_parent_and_sibling_and_global_never_other_projects`. The additional
`requireTwoFactor` consultation described for (a) is **built** since 2026-10-24 (§10.4).

**(d) Anything requests an orphaned entry.** — **built** (the denial); **planned** (the exception)
R0 → DENY before any other consideration, on every transport that exists. The response says the
entry exists, is sealed, and can only be opened by a human at the machine. Names are not hidden;
values are not reachable. The native-app-with-presence exception in R0 is real code and is fuzzed
by I-17, but no transport can reach it (§4, step 4), so today R0 is a total denial with a
documented door that nothing can open yet.

**(e) A locked vault, and a reveal that would otherwise be allowed.** — **built**
R1 denies. The broker then re-runs the same request with the lock ignored; if that would have been
allowed, the caller gets `approval_pending` with a request id and a countdown instead of a denial,
and a human can approve that one request. If it would have been denied anyway, the ordinary §5
denial is returned — locking the vault must never turn an unreachable node into a notification.
`crates/brokerd/tests/isolation.rs::i14_locked_vault_still_lists_topology_but_reveal_requires_approval`.

---

## 8. A real requirement, worked through: infrastructure that belongs to no project — **partial**

The node model exists to answer exactly this shape of requirement, so it is worth working through
end to end rather than leaving it abstract. Every step below is **built** except step 3 — drawing
the one grant — which refuses for the reason §6 gives.

**The requirement, as it actually arises for V1 users:** a piece of infrastructure — a legacy
server, a shared account, a piece of hardware — that is closed and self-use. It belongs to no
project, and only one specific project's agent should ever be able to read or connect to it.

**Why V1 cannot do this.** `project` in V1 is a filter string with no enforcement behind it —
`03_DATA_MODEL.md`'s whole argument. A credential tagged with one project name is exactly as
reachable to every other agent as one tagged global; the tag changes what shows up in a filtered
`list`, nothing else. The only control V1 has is a paragraph in that project's own instructions
file asking every agent nicely not to touch it — a convention, not a boundary.

**The V2 mapping needs no new mechanism — it is the default, applied deliberately:**

```
                         ┌────────┐
                         │ GLOBAL │
                         └───┬────┘
        ┌───────────┬────────┼────────┬────────────┐
    ┌───┴───┐   ┌────┴────┐ ┌┴──────┐ ┌┴──────────┐
    │ acme  │   │northwind│ │contoso│ │ fabrikam  │   ← depth 1, all siblings
    └───────┘   └─────────┘ └───────┘ └─────┬─────┘
                                             ╎
                                             ╎ ← ONE human-created grant:
                                             ╎    fabrikam → legacy-box (read, reveal)
                                             ╎    reason: "fabrikam's agent needs this box's
                                             ╎    tunnel front and remote login"; reviewed,
                                             ╎    expiring, revocable in one click
                                       ┌─────┴──────┐
                                       │ legacy-box │   ← depth 1, sibling to every project
                                       └────────────┘
```

1. `legacy-box` is created as an ordinary depth-1 node, sibling to every project. **It is isolated
   from `acme`, `northwind`, and `contoso` by R8 with zero configuration** — that is simply what a
   fresh sibling node is. "Off limits to everyone" is not a policy to set; it is what happens if
   you do nothing further. `node.create` builds it for real, generating and wrapping its node key
   in the same call so it is immediately usable (ADR-051).
2. `fabrikam` is created the same way.
3. **One grant**, `fabrikam → legacy-box`, drawn by the operator on the graph or with
   `credmgr grant fabrikam --to legacy-box --scope read,reveal --reason "…"`, behind 2FA and
   presence (§6). This is the *only* path by which `fabrikam` — or anything else — ever reaches
   `legacy-box`. **This step is the one that does not execute today**: the command reaches
   `grant.create`, which validates it and answers `presence_required`.
4. No other node ever gets access without its own separate grant. `acme` requesting anything on
   `legacy-box` hits R8 exactly as trace (b) above, with `subject: acme, target: legacy-box,
   rule: R8` in the denial — indistinguishable from any other cross-project request, because that
   is what it is.

**What this buys over V1's convention:** an agent working on `acme` cannot reach `legacy-box` by
*construction*, not by choosing to follow an instruction. A prompt-injected or careless agent
gains nothing by trying — R8 fires before any node key is touched. `fabrikam`'s access is itself
capability-scoped (`read`/`reveal` only, never `admin`, because `grant.create` refuses to mint any
other scope), time-bounded if the grant expires, and shows on the graph as a single dashed line
anyone can see and revoke.

**Migration note.** Per `11_MIGRATION.md`, V2 does not import V1's vault — but when an operator
with this shape of requirement sets up V2 by hand, this is the first pair of nodes worth creating
deliberately, precisely because it is the case where V1's "ask nicely" model was already known to
be insufficient.

---

## 9. Sealing, the orphan node, and the restore window — **built**

Removing a node does not delete it. It **seals** it: the node's entries are re-encrypted to the
orphan node's public key (the private half is the cold key, `04 §5.2`), its registry entry is removed and
replaced by a signed seal record (ADR-079), and its own key is retained in the 7-day archive. Names survive;
values become reachable only by a human at the machine, through R0's native-plus-presence door.
Sealing is one of the four promises the product makes, which is why R0 sits above every other rule
and why no grant, policy or token can override it.

For seven days a sealed node can be restored byte-identically, across restarts; after that restore is
refused and the caller gets `archive_expired` (destroying the expired archive and its node key is a
separate step nothing schedules yet — `04 §5.1`). The window is a soft-delete recovery period and
is unrelated to audit-log retention, which is twelve months (`03_DATA_MODEL.md §9`) — the two
numbers have been conflated before and are different mechanisms.

**The authorisation subtlety, and a real hole that was closed.** `node.seal` gates on two things:
the token holds `Capability::Admin`, *and* `resolve` allows `admin` against the node being sealed.
`node.restore` — the exact inverse operation on the exact same data — originally gated on only the
first, because the node no longer has a registry entry to resolve against. The premise was true;
the conclusion did not follow. An `admin` token scoped to project `b` was correctly refused when it
tried to seal project `a`, and **accepted** when it asked to restore `a`. That let one project
unilaterally undo another's security action, moving deliberately-sealed values back into agent
reach.

`node.restore` now makes the same `resolve` call `node.seal` makes, against the same node id
(ADR-053). It resolves correctly **because** the node is absent, not in spite of it:
`is_strict_ancestor` returns false for a node it cannot find, so R4/R5/R6 cannot fire; R3 needs the
target to *be* global; R7 needs a grant against a node that is gone. The only rule that can still
allow is **R2** — the node restoring itself, which is how every legitimate path has always worked.
Everything else lands on R8.

Two consequences worth stating rather than discovering later. An ancestor holding `admin` can no
longer restore a sealed descendant, because the relationship cannot be established once the node is
absent — a real narrowing, in the safe direction, consistent with D-01. And a caller holding
`admin` somewhere can still distinguish "a sealed node by that name exists but I am denied" from
"no such sealed node"; collapsing those would cost the `not_found` / `archive_expired` distinction
the seven-day assertion depends on, to withhold an id the caller very likely already knew.

**Evidence.** `crates/brokerd/tests/isolation.rs::i21_seal_then_restore_day_6_succeeds_byte_identical_day_8_is_gone`
and `::i21b_restore_is_refused_to_an_admin_token_from_an_unrelated_node`, the latter written to
fail first against the hole above, and it did.

---

## 10. The finished access graph — what is designed and not yet built

Everything in this section exists nowhere in `v2/crates/**` or `v2/apps/**`, except the tightening
half of §10.1, built on 2026-09-24 (ADR-071) and described there in the present tense. The rest is
written out in full because the corpus's job is to describe the destination, and it is written in
the future tense because none of it runs.

### 10.1 Node policy is writable by partial patch — `partial`

Six policy fields govern rule outcomes — `siblingVisibility` (R6), `descendantRead` (R5),
`requireTwoFactor`, `lockAfterSeconds` (§1a), `privateNames`, `agentAccess` (§3). Until 2026-09-24
no operation read or wrote any of them. **`node.policy` is now built** (ADR-071) as this section
designed it: a single operation taking a partial policy patch — unknown fields refused, an empty
patch refused — gated like `node.set_workdirs` (ADR-066): never `Origin::Agent`, `Capability::Admin`
as a ceiling, `resolve` for `admin` against the node being changed, and a mandatory reason
(≤ 500 characters) written into the audit record's `detail`. Every change that tightens or is
neutral — the other four fields, and turning either widening field back off — applies at once,
behind the admin gate alone. A policy change drops every gate elevation
(`07_TWO_FACTOR.md §5`). The resulting policy comes back in the op's own response, which is the
only place any op returns it; `node.create` still applies the defaults, and
`node.set_workdirs` edits `workdirs`, not policy. The sibling op `node.update` (ADR-071) renames a
node — any but Global and Orphan — and touches no policy field.

**What is not built.** The two fields that widen reachability — turning `descendantRead` on, or
`siblingVisibility` to `shared` — need the full presence gate, because turning either on has
precisely the effect §6a describes for re-parenting. Presence is not attestable on any transport
yet (§10.3), so such a patch answers `presence_required` and **nothing in it is applied** — the
patch is all-or-nothing. `requireTwoFactor` and `privateNames` are enforced since 2026-10-24
(§10.4, ADR-085, ADR-083); the response's `notEnforced` list is therefore empty (the key stays for clients
that read it). The confirmation dialog
will enumerate the newly-readable and newly-unreadable nodes the same way §6a's does, computed the
same way: `resolve` against a scratch clone, differenced. So R5 and R6 can be narrowed by an
operation today, and widened only in tests and by editing `registry.json` by hand.

**Evidence.** `crates/brokerd/tests/durable_vault.rs::node_policy_tightens_at_once_refuses_a_widening_without_presence_and_records_why`
and `::node_update_renames_a_node_and_the_label_survives_a_restart`.

### 10.2 `grant.create` will execute — `planned`

The operation is written and refuses only for want of presence (§6). When §10.3 lands, the terminal
`PresenceRequired` will be replaced by the write path: append the `Grant` to the registry with
`createdBy: 'human'`, persist, and audit. Two follow-on decisions belong to that session rather
than this document: whether `list` becomes a grantable scope so that entry-level grants can be
minted through the operation that §1b's narrowing already honours, and whether `direction:
'mutual'` is exposed in the dialog at all or remains a registry-level shape only.

### 10.3 The native origin and presence attestation — `planned`

`resolve_scope` will gain a fourth branch: a request arriving over the desktop shell's own channel,
carrying a presence proof produced by the platform biometric API immediately before the call, will
resolve to `origin: 'native'` with `presence_attested: true`. Everything downstream already exists —
R0's exception; five of the six `presence_required` return sites (`audit.get`, `totp.seed`,
`node.reparent`, `grant.create`, `maintenance.doctor --rebuild-registry` — §3) — the sixth,
`node.policy`'s refusal of a widening patch (§10.1), does not consult `presence_attested` yet and
will need its refusal replaced by that check; and the
`PresenceProof` type, already defined as part of the `PlatformKeystore` trait contract in
`crates/keystore`. The Tauri bridge's own command surface carries no `PresenceProof` today —
only the literal error string `"presence_required"` in its error mapper — because there is nothing
for the bridge to hold until this branch exists. The proof will be verified by the broker, not
trusted from the client:
the desktop shell holds its session token in Rust and never lets the webview see it (ADR-057), and
presence will follow the same custody rule. Until this lands, every lock icon that implies presence
is doing less than a reader would assume, which is why this document says so in four places rather
than once.

### 10.4 Per-node two-factor on reveal — `built` against the vault gate (ADR-085); a per-node gate `planned`

`requireTwoFactor` is consulted at `entry.reveal` and `totp.code` time (level `reveal`, the default) and at
every read of the node (`entry.list`, `entry.get`, `notes.read`, `vault.pending_list`; level `always`), not only at
unlock — but only when the vault gate is confirmed. A reader that is not the owner's own login gets
`two_factor_required` (`challenge: "totp"`) until a person proves the second factor with `vault.gate_verify`
(mid-session this is a step-up that mints no token and opens a five-minute elevation). Built: `part4_two_factor.rs`.
Still `planned`: a *per-node* gate secret and a per-node elevation (the factor and the window are the vault's), and a
screen for the step-up.

### 10.5 Anomalies will be emitted, not only counted — `planned`

The cross-node denial counter (§7b) will raise an event on the request that trips it: an audit
record distinct from the individual denials, a desktop notification, and a banner in the UI. The
other anomaly rules `05_THREAT_MODEL.md §8` names — an orphan-reveal attempt from a non-native
transport, a registry HMAC failure, an unlock from a new executable path — will join the same
channel. Only `anomaly.token_workdir_mismatch` is emitted today.

### 10.6 The graph will show grants — `planned`

`graph.snapshot` returns nodes and `kind: "structural"` parent links, filtered to what the caller
may `list`. It emits **no grant edges at all**, so the dashed line this document describes in §2,
§6 and §8 has no data behind it yet. The target design adds a second link kind for grants, subject
to the same visibility filter on both endpoints — a grant between two nodes a caller cannot see
must not be inferable from the graph — plus the direction, scope and expiry a hover card needs
(`09_UI_UX_SPEC.md §10`).

### 10.7 Delegated administration, and the R3 question it reopens — `planned`

Today `admin` is reachable only at `global`, which is what makes R3's capability-unqualified ALLOW
harmless. A per-node delegated-admin role — an operator who may administer one project and no other
— would mint an `admin` token scoped to a non-global node, and R3 would then let that token
administer `global` too. That is the session that must narrow R3, and it must do so before the role
exists rather than after. Recorded here so it is a decision on the record rather than a silently
expired note.

---

## 11. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `04_CRYPTO_AND_KEYS.md §3` | the per-node X25519 keypair that makes a denied node's ciphertext unopenable, not merely unrequested |
| depends on | `04_CRYPTO_AND_KEYS.md §4` | the soft-grant decision — why revocation is one registry write and why a compromised broker collapses every rule here |
| depends on | `03_DATA_MODEL.md §1` | the `Node` shape, the depth cap, and the six policy fields R5/R6/§1a read |
| depends on | `03_DATA_MODEL.md §6` | the `Grant` shape, its `read`/`reveal`/`notes` scope type, and `direction: 'mutual'` whose enforcement §1c defines |
| feeds | `05_THREAT_MODEL.md §8` | the denial and anomaly events detection is built on, and the counter §7b reports as unwired |
| feeds | `07_TWO_FACTOR.md §2` | which operations the gate stands in front of, and §10.4's per-node consultation it does not yet perform |
| feeds | `10_API_AND_MCP.md §1` | the `node_access_denied` wire shape §5 fixes, field for field |
| feeds | `10_API_AND_MCP.md §3` | the capability each MCP tool is checked against, and the forbidden-op list that keeps grant creation off the agent surface |
| feeds | `13_TEST_PLAN.md §4.1` | the isolation suite's rule coverage — I-1…I-9, I-11, I-12, I-14, I-16, I-17, I-21…I-24 all assert against this document |
| feeds | `18_ENDPOINT_INDEX.md §1` | the built/planned status of every `grant.*` and `node.*` operation |
| feeds | `09_UI_UX_SPEC.md §10` | the grant dialog's required inputs and the revoke affordance §6 specifies |
| feeds | `22_ORG_VAULT_SYNC_AND_LICENSING.md §4` | the rule set an organisation vault's departments must not quietly widen |
| depends on | `14_DECISIONS.md` | `ADR-050` (grant ops gate on `to`), `ADR-051` (`node.create`'s parent-resolved admin gate, and the R3 question it deferred), `ADR-053` (`node.restore`'s cross-node hole, §9), `ADR-056` (session login, the only path to `admin`), `ADR-057` (the bridge's token custody), `ADR-059` (the status vocabulary this rewrite applies), `ADR-065` (a real login evaluated as the target node), `ADR-066` (settable workdirs), `ADR-071` (`node.update`, `node.policy`), `ADR-072` (`notes.*` behind the `notes` capability) |

## 12. Source

**Design.** `ADR-050`, `ADR-051`, `ADR-053`, `ADR-056`, `ADR-057`, `ADR-062`, `ADR-065`, `ADR-066`,
`ADR-071`, `ADR-072`
in `14_DECISIONS.md`; Pass 2
findings F-1 (the `create`/`update` split), F-6 (reachable-only listings), F-7 (node-level lock),
F-8 (re-parenting as scope widening), F-13 (revoke in both modes) and F-14 (entry grants are not
listings) in `15_PASS2_REVIEW.md`.

**Code.** `crates/core/src/access.rs` — `resolve`, the R0–R8 ladder, `has_matching_grant` including
the mutual branch. `crates/core/src/registry.rs` — `Capability`, `NodePolicy` and its defaults,
`Direction`, `GrantTarget`, `is_strict_ancestor`, `are_shared_depth2_siblings`.
`crates/brokerd/src/scope.rs` — `resolve_scope`'s three built branches and
`capabilities_for_agent_access`. `crates/brokerd/src/ops.rs` — `resolve_capability` (which
hard-codes `presence_attested: false`), `subject_for` (ADR-065's owner-session subject),
`canonical_workdirs` and the `node.set_workdirs` arm (ADR-066), `narrow_entries`,
`access_denied_error`, `human_admin_on` and `PolicyPatch` (ADR-071), `notes_gate` (ADR-072), and the 53 dispatched ops. `crates/brokerd/src/protocol.rs` — the `node_access_denied` serialisation §5 quotes.
`crates/brokerd/src/rate_limit.rs` and `crates/brokerd/src/server.rs` — the denial counter and the
call site that discards its trip.

**Tests.** `crates/core/tests/access_matrix.rs` (§2's grid, cell by cell);
`crates/core/tests/isolation_i17.rs` (I-17, independent rule re-derivation over random 30-node
graphs); `crates/core/tests/properties.rs` (P-9 default-deny, P-10 monotone in grants);
`crates/brokerd/tests/isolation.rs` I-1…I-9, I-11, I-12, I-14, I-16, I-21, I-21b, I-22, I-23, I-24 and — ADR-078 — I-27 (`entry.get` and the field ops obey the graph exactly as `entry.update` does), I-28, I-29;
`crates/brokerd/tests/grant_ops.rs`, `node_ops.rs`, `graph_snapshot.rs`, `session_login.rs`,
`durable_vault.rs` (the owner session's reach; a bound workdir scoping an agent).
`cargo test --workspace -- --list`: 813 tests in 50 test binaries (2026-10-03); the last full run recorded: 571 passing, 0 failing, 41 test binaries, exit 0 (2026-10-02; earlier: 448 passing, 37 test binaries on 2026-09-24, re-measured 2026-10-01; 406 passing, 35 test binaries on 2026-09-13 — run
`34743281942`; 397 passing, verified 2026-08-18).
**I-10 is implemented nowhere** — accepted risk K-1 in `PHASE8_AUDIT_REPORT.md`; no test in this
corpus should be cited as covering it.

**Verification.** `python3 -m tools.corpus_check crossrefs` for every `NN_NAME.md §S` reference
above; `python3 -m tools.corpus_check endpoints` for every operation name this document asserts is
built.

**Figures.** `access-rule-ladder` (§1, `docgen` `kind: "flowchart"`) and
`grant-lifecycle-built-vs-planned` (§6, `docgen` `kind: "state"`) are built. Both render from
`06_ACCESS_GRAPH_spec.json`, beside this document, per `ADR-060` and
`tools/ENGINE_ROUTING_POLICY.md`. The ladder's nodes/edges are transcribed from `resolve()`'s
literal branch order (`crates/core/src/access.rs:142-219`); the lifecycle's built/planned split is
transcribed from the `grant.create`/`grant.revoke` arms (`crates/brokerd/src/ops.rs:2513-2619`) and
`has_matching_grant`'s expiry check (`crates/core/src/access.rs:102-125`).
