---
id: V2-015
classification: public
title: Pass 2 adversarial review (record)
audience: technical
owner: credmgr-v2
status: needs-verification
export_allowed: true
surface: repo
last_reviewed: 2026-08-18
---

<!-- artifact-hardened: NEEDS RE-HARDENING — a dated adversarial-review record. Its body is deliberately unchanged by the
     2026-08-18 corpus rewrite; only the front matter required by ADR-058 was added. A record is
     evidence of what a review found on a date, and is never revised to match a later state.
     Three wording changes were made in F-12 only: the literals it used for the loopback address
     were replaced by the concept each named, because docgen's Gate 3b blocks them and the record
     could not build at all otherwise. No finding, severity or outcome was altered — recorded here
     so an edit to a record is auditable rather than silent. -->
# Pass 2 — adversarial review of the Pass 1 design

`CredMgr V2` · `2026-08-04`
**Method:** read Pass 1 as an attacker and as a maintainer, hunting for (a) security claims
without mechanisms, (b) internal contradictions, (c) states nobody designed, (d) operations
that can strand the operator, (e) my own stated principles violated elsewhere in my own docs.

**Result: 21 findings.** 14 forced edits to the Pass 1 corpus (applied — see §4).
7 are accepted with a stated bound.

---

## 1. Findings — security and correctness

### F-1 · Write-while-locked enables credential substitution — **HIGH** — *fixed*

Pass 1 boasted that asymmetric node keys let anyone encrypt an entry to a locked node. That
is true, and it means **an attacker who can write to the vault directory can silently replace
an existing credential with one they control**. The operator then uses the attacker's
password against the attacker's server. Encryption does not help — the substitute is
perfectly valid ciphertext.

Worse, "write-only agent" — which Pass 1 sold as a security *feature* — is precisely the
capability needed to pull this off from inside the API.

**Fix (applied to `04 §3`, `06 §3`, `09 §7`):** split the capability.

- `create` — new entry, new name. Permitted while locked. Lands in a **pending tray**.
- `update` — modify an existing entry. **Requires the vault unlocked**, because a legitimate
  update means you could have read the old value.

Everything written while locked goes to `nodes/<id>/pending/` and is surfaced at next unlock
as *"3 entries were added while locked — review"*. Nothing enters the manifest until a human
accepts it. The feature survives; the substitution attack does not.

### F-2 · Per-node manifests were unsigned — **HIGH** — *fixed*

`registry.json` is HMAC-signed. `nodes/<id>/manifest.json` was not. An attacker could delete
an entry from a manifest (making a credential invisible while the envelope sits on disk),
alter counts, or repoint an entry id at a different envelope file.

**Fix (applied to `03 §8`, `04 §6`):** every manifest carries an HMAC under
`HKDF(RK, "manifest-hmac/" + nodeId)`, and `registry.json` records each node's
`manifestGeneration` + `manifestHmac`. The two are cross-bound, so neither can be rolled back
independently of the other.

### F-3 · Rollback attack on the registry — **HIGH** — *fixed*

An HMAC proves authorship, not freshness. An attacker who kept yesterday's `registry.json`
can restore it — reinstating a revoked grant, loosening a tightened policy, or resurrecting a
sealed node's key reference. Every byte verifies correctly.

**Fix (applied to `03 §2`, `04 §6`):** a monotonic `vaultGeneration` counter is stored
**outside the vault directory**, in the macOS Keychain as a small owner-only item, and mirrored
into the SE-wrapped root blob. The broker refuses to open a registry whose generation is lower
than the last value it saw. Rollback becomes a loud failure with a named remedy instead of a
silent policy reversal.

### F-4 · The 7-day restore window was cryptographically impossible — **HIGH** — *fixed*

`04 §5` said sealing re-encrypts to the orphan key and discards the plaintext; `09 §9` promised
"Restore node puts everything back intact" for 7 days. But restoring would then need the
**orphan private key** — the cold key that requires presence and a fresh code per item. The
promised one-click restore could not work.

**Fix (applied to `04 §5–6`, `09 §9`):** sealing writes the orphan copy **and retains the
original envelopes plus the node's private key in `archive/<sealedId>/` for 7 days**. Restore
within the window is a move, needing only the retained key. At day 7 the archive and the node
key are destroyed and only the orphan copy remains. The archive inherits the node's directory
mode and is covered by `verify`.

### F-5 · Two documents disagreed about what the recovery code opens — **MEDIUM** — *fixed*

`04 §2` implied the printed recovery code alone unwraps the root key. `07 §4` said the
passphrase *and* the recovery code together re-enrol the gate. Read together, a reader could
conclude a single printed card opens the vault.

**Fix (applied to `04 §2`, `07 §4`):** stated explicitly — **any one of the three wraps
recovers the root key, and gate 2FA is still required afterwards before any node key is
loaded.** A stolen recovery card is one factor, not the vault. The passphrase + recovery-code
pair is specifically the path to *re-enrol a lost gate* once all ten gate recovery codes are
spent, which is a different operation and now reads as one.

### F-6 · `credmgr_whoami` leaked the topology — **MEDIUM** — *fixed*

Pass 1 had it return "the list of nodes it can reach". Left as written, the obvious
implementation returns the node list and marks reachability — handing an agent every project
name on the machine.

**Fix (applied to `10 §3.1`):** `whoami` returns **only** the caller's own node and the nodes
it can actually reach. Nodes outside scope are not named, not counted, and their existence is
not implied. An agent's world is its own subtree.

### F-7 · Node-level lock was referenced but never designed — **MEDIUM** — *fixed*

Rule R1 in `06 §1` gates on "node-level lock", a concept that appeared nowhere else. A
dangling rule is worse than a missing feature: an implementer either invents semantics or
silently drops the rule.

**Fix (applied to `06 §1`, `09 §3`, `09 §5`):** specified. A node can be locked individually
while the vault stays unlocked — its keys leave the hot set, `reveal` fails, `list` still
works. Intended for the wallet node. Set from the node context menu and by policy
(`lockAfterSeconds`). Rendered as the keyhole glyph already defined in the visual language.

### F-8 · Re-parenting silently widens access — **MEDIUM** — *fixed*

Grants are gated behind 2FA and presence. Moving a node under a different parent changes its
ancestor set, and therefore what it can read, with the same effect as a grant — but Pass 1
treated it as an ordinary edit.

**Fix (applied to `06 §6`, `09 §9`):** re-parenting is a **scope-widening operation** and
carries the full grant gate: 2FA, presence, a reason, and an audit record. The confirm dialog
enumerates exactly which nodes become newly readable.

### F-9 · No concurrency model — **MEDIUM** — *fixed*

CLI, UI and one MCP server per agent can all write at once. Pass 1 said nothing, which means
last-writer-wins on manifests and a lost entry.

**Fix (applied to `02 §2`, `03 §8`, `10 §1`):** the broker serialises writes per node with an
exclusive in-process lock, and every mutating request carries the caller's last-seen
`generation`. A stale generation returns `conflict` with the current state rather than
overwriting. Reads are never blocked.

### F-10 · Refusing to start on a registry failure could strand the operator — **MEDIUM** — *fixed*

`fail-closed` is right, but Pass 1 gave no way back. A corrupt or rolled-back registry meant a
vault that never opens again.

**Fix (applied to `02 §7`, `12` Phase 2 gate):** a recovery mode.
`credmgr doctor --rebuild-registry` reconstructs the registry from the per-node manifests and
the most recent signed backup, requires presence + gate 2FA, shows a full diff of what
changed (nodes, grants, policies) before writing, and records the rebuild in the audit log.
Fail-closed with a documented door, not a wall.

### F-11 · Alias collisions during migration — **MEDIUM** — *fixed*

Migration registers a short alias (`SERVER_PASSWORD`) for every long name. Two entries in the
same node can collide — `ACME_SERVER_PASSWORD` and `ACME_SERVER2_PASSWORD` both shorten toward the
same stem — and Pass 1 had no rule.

**Fix (applied to `11 §3`):** aliases are unique per node. On collision the alias is **not**
registered, and both entries appear in the migration report's `alias-skipped` section for the
operator to resolve by hand. Never auto-suffixed — a silently renamed alias is worse than none.

### F-12 · A loopback-bound static server contradicted "no HTTP surface" — **MEDIUM** — *fixed*

`02 §2` had the UI process serving assets over a loopback HTTP listener; `10 §5` claimed no HTTP surface.
Both were defensible (static assets carry no secrets), but a listening port is reachable by
every local process and is exactly the kind of thing that later grows an endpoint.

**Fix (applied to `02 §2`, `10 §5`):** **no listening socket at all.** The native shell serves
the UI through a `WKURLSchemeHandler` on a custom scheme, reading from the app bundle. The
browser-based dev server exists only in development, is loopback-bound, refuses to start
against a real vault, and is excluded from release builds by a build-time check.

### F-13 · Lite hid a safety lever — my own principle, violated — **MEDIUM** — *fixed*

`09 §1` states "Lite hides levers, never safety". `09 §5` then hid **grant management**
entirely in Lite. Creating a grant is a lever. **Revoking one is safety.** A Lite user who
discovers a grant they no longer want could not remove it.

**Fix (applied to `09 §5`):** in Lite, grants are visible and **revocable**; only *creation*
is Pro. Same reasoning applied to a second case found on re-read: sealed-node **restore** is
now available in both modes.

### F-14 · Entry-level grants were under-specified — **LOW** — *fixed*

`03 §6` allows `to.kind: 'entry'`, but rule R7 in `06 §1` only says the grant "covers the
target".

**Fix (applied to `06 §1`, `06 §3`):** an entry grant authorises exactly that entry. `list`
against the granted node returns **only** the granted entries — not the node's full inventory —
so an entry grant does not become a directory listing.

---

## 2. Findings — usability and operations

### F-15 · Auto-lock versus long agent sessions — **MEDIUM** — *fixed, and improved*

A 15-minute auto-lock will interrupt an hour-long agent run. The tempting fix — a long
agent-session unlock — reintroduces exactly the always-unlocked vault the design is trying to
end.

**Fix (applied to `07 §5`, `09 §11`, `10 §1`):** no agent bypass. Instead, **approval on
demand**: a `reveal` against a locked vault returns `approval_pending` and raises a macOS
notification. One Touch ID tap approves that single request; the vault does not unlock. The
agent sees a short, bounded wait and a clean allow or deny. The MCP tool description tells
agents to fetch what they need up front and to expect a possible approval wait.

This is better than what Pass 1 had, not merely a patch: the operator now sees *what* is being
asked for at the moment it is asked, which is the highest-value security signal in the system.

### F-16 · Nothing scheduled a backup — **MEDIUM** — *fixed*

Pass 1 had a backup command and a retention flag but no automatic backup, in a product whose
top-priority threat (`05`, A3) is operator error.

**Fix (applied to `09 §5`, `12` Phase 2):** automatic encrypted backup daily and before every
destructive operation (seal, destroy, re-key, migration), retaining 14, in **both** modes.
Lite shows only "last backup: 2h ago".

### F-17 · TOTP depends on the system clock — **LOW** — *fixed*

A drifted clock makes every gate code fail, which presents as "2FA is broken" and invites the
operator to disable it.

**Fix (applied to `07 §5`):** on three consecutive failures the broker compares its clock
against the code's implied window and, when the pattern matches drift, says so:
*"Your codes are failing consistently by about 90 seconds — check the system clock."*
`credmgr doctor` reports clock skew.

### F-18 · Search behaviour under lock was unspecified — **LOW** — *fixed*

**Fix (applied to `09 §6`, `09 §13`):** locked → entry **names** only (they live in the
plaintext manifest). Unlocked → names, field labels and notes. Values are never searched, in
either state. Orphaned entries appear by name only and are never previewable. Every result
carries its owning node.

### F-19 · Export scope was undefined — **LOW** — *fixed*

**Fix (applied to `04 §7`, `10 §2`):** exports contain entry values only. Never notes, never
gate secrets, never TOTP seeds, never the audit log. `--include-notes` exists, requires
presence, and prints a warning.

---

## 3. Accepted without change

| # | Finding | Why accepted |
|---|---|---|
| **A-1** | A grant's mandatory `reason` can be filled with garbage | Unenforceable by validation. Mitigated by surfacing the reason in the grant list and the stale-grant sweep, where garbage is visible and embarrassing. |
| **A-2** | An attacker with vault-directory write access can seal or delete entries (denial of service) | They can already delete the files. Sealing via the API needs unlock + 2FA + presence. No additional exposure. |
| **A-3** | Depth cap of 2 will eventually frustrate someone | ADR-004. Widening is a small change to one rule; starting deep is not reversible. |
| **A-4** | `resolve()` has 8 rules — more than a one-liner | Each rule maps to a stated product promise, and all 64 cells of the 8×8 matrix are table-tested. Fewer rules would mean implicit behaviour. |
| **A-5** | Node.js heap zeroisation remains best-effort | AR-3 / ADR-009. Unchanged by this review. |
| **A-6** | Broker compromise defeats grants and exposes the hot set | AR-2 / AR-4. Inherent to any always-on agent; the alternative loses instant revocation. |
| **A-7** | Entry *names* stay in the plaintext manifest (Q-2) | Encrypting them would make the locked graph and locked search impossible, which are two of the features that make locking cheap enough to actually happen. Recorded as AR-1; the operator can overrule via Q-2. |

---

## 4. Edits applied to the Pass 1 corpus

| Doc | Sections changed | Findings |
|---|---|---|
| `02_ARCHITECTURE.md` | §2 (no listening socket, write serialisation), §7 (recovery mode, archive retention) | F-9, F-10, F-12 |
| `03_DATA_MODEL.md` | §2 (vaultGeneration), §6 (entry grants), §8 (manifest HMAC + generation) | F-2, F-3, F-9, F-14 |
| `04_CRYPTO_AND_KEYS.md` | §2 (recovery clarified), §3 (create vs update), §5 (archive retention), §6 (lifecycle rows), §7 (export scope), §9 (residual table) | F-1, F-2, F-3, F-4, F-5, F-19 |
| `06_ACCESS_GRAPH.md` | §1 (R1 node lock, R7 entry grants), §3 (create/update split), §6 (re-parenting gate) | F-1, F-7, F-8, F-14 |
| `07_TWO_FACTOR.md` | §4 (recovery path), §5 (approval-on-demand, clock drift) | F-5, F-15, F-17 |
| `09_UI_UX_SPEC.md` | §3, §5 (Lite revoke + restore, auto-backup), §6 (search under lock), §7 (pending tray), §9 (re-parent gate, restore), §11 (approval), §13 | F-4, F-7, F-8, F-13, F-15, F-16, F-18 |
| `10_API_AND_MCP.md` | §1 (generation/conflict, approval_pending), §2 (export scope), §3.1 (whoami scope) | F-6, F-9, F-15, F-19 |
| `11_MIGRATION.md` | §3 (alias collisions) | F-11 |
| `12_BUILD_PLAN.md` | Phase 2 + 3 gates | F-2, F-3, F-10, F-16 |
| `13_TEST_PLAN.md` | §3 (I-18…I-24) | F-1, F-2, F-3, F-4, F-6, F-8, F-14 |
| `14_DECISIONS.md` | ADR-023…ADR-027 | F-1, F-3, F-12, F-15 |

---

## 5. Verdict

**Status: `Approved With Known Risks`.**

All quality gates pass with cited evidence. The named risks are AR-1 through AR-6
(`05_THREAT_MODEL.md §6`), each with an explicit bound, an owner (the CredMgr agent), and a
resolution path or an accepted-permanently rationale.

**The design is ready to build.** The corpus is self-contained: a session that has never seen
this conversation can execute `12_BUILD_PLAN.md` from Phase 1 without asking a question,
because every decision it would need to make is in `14_DECISIONS.md` and every open question
has a working default.

**What Pass 2 changed about the design's honesty.** Pass 1 sold write-while-locked as a pure
win; it was an attack surface. Pass 1 promised a restore that the cryptography made
impossible. Pass 1 violated its own "Lite hides levers, never safety" rule two sections after
stating it. None of those would have been caught by building carefully — they needed the
design to be read adversarially, once it existed. That is the entire argument for the second
pass, and it earned its place here.
