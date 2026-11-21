---
id: V2-010
classification: public
title: API and MCP surfaces
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-19
---

<!-- artifact-hardened: NEEDS RE-HARDENING — revised 2026-11-08 for ADR-150 (reveal confirmation); awaiting re-verification. Earlier: edited 2026-11-06 for ADR-098 (Touch ID honesty pass). Earlier note: rewritten to ultimate-destination state on
     2026-08-18 (Session 21). The previous stamp (Approved With Known Risks @ d15a5c7, pass 2,
     reconciled 2026-08-10 under ADR-052) had drifted and was invalid: the body was edited after
     the commit it named. This rewrite invalidates it again by construction. Every claim below
     was re-derived from live source in this pass, and the pass found two real defects in the
     built MCP surface that no document or test had recorded (§3.1a). The corpus-wide hardening
     stamp is the operator's to assign after their own review, not this session's to self-award.

     Closed against the S21 verification backlog, 2026-08-18, same day: §3.1a's tool-coverage
     count was wrong twice over (`credmgr_list` is exercised by `mcp_integration.rs`; the tools
     it does not exercise are five, not two, and only `credmgr_search` is unexercised anywhere in
     the workspace); the §8 Connections row and the §7 "No remote or sync surface" citation both
     pointed at the wrong section of `13_TEST_PLAN.md`/`05_THREAT_MODEL.md`; and §4.1 counted
     `totp.seed` among the 34 built-and-reachable ops when it is one of the four in §4.2. All four
     re-derived from live source before the fix, per `VERIFICATION_BACKLOG_S21.md`. A fifth,
     unlisted defect of the same shape as one already recorded against `03_DATA_MODEL.md` was
     found and fixed in the same pass: §1.4's generation-conflict row claimed "every mutating
     request", which `entry.create` (ops.rs:1179) contradicts — it bumps `generation` but never
     reads `params.generation`.

     Closed against the S21 round-2 verification backlog, 2026-08-19: three more defects, all
     re-derived from live source before the fix. (1) §3.1a's own "only `credmgr_search`" line was
     itself wrong — `credmgr_update` and `credmgr_undo` are equally never named in a `tools/call`
     anywhere in the workspace (confirmed by grepping the three tool names across every `.rs` file
     in `v2/`: each appears only in its own registration in `crates/mcp/src/tools.rs`); three
     tools are unexercised, not one. (2) §2.1 and §9 both claimed a mechanical arm-count of 24 for
     the nested `node`/`grant` subcommand arms; a literal count of every quoted match arm in
     `crates/cli/src/main.rs::run` gives 26, because `cmd_gate`'s own nested `"verify"` arm
     (line 249) was omitted from both counts. (3) §3.3 described a "planned" message-reasoning
     enrichment sourced to `06_ACCESS_GRAPH.md §5` that section does not describe as planned
     anywhere — §5 explicitly retracts that exact example ("Nodes at depth 1 are isolated by
     design.") as stale text the broker never emitted, and `06`'s own §10 list of planned
     access-graph work does not mention a reasoning-clause enrichment either. Still NEEDS
     RE-HARDENING: this is a defect-closure pass, not the operator's own review. Updated
     2026-09-24 for ADR-062…066 (42 ops, the honoured unlock passphrase, the new CLI commands,
     the 23-variant error taxonomy, the fully bridged shell). Updated 2026-09-24 for ADR-071…073
     (47 ops: `node.update`, `node.policy`, `notes.read`/`notes.write`, the single-value
     `entry.create_batch`; both node ops on the MCP forbidden list; the error taxonomy recounted
     at its actual 24 variants). Updated 2026-10-02 for ADR-075…077 (48 ops: `maintenance.rotate_root`
     built behind its presence wall; the 25-variant taxonomy gains `node_locked`; the CLI gains
     `import`, `notes` and `node rename`/`policy`; no bearer in the audit log; additive
     `entry.list`, `vault.status` and `notes.read` fields; the `two_factor_required` scope example
     corrected from `"vault"` to the `"global"` the broker emits). Updated 2026-10-03 for ADR-078/079
     (53 ops: `entry.get` and the four `field.*` operations built, the field-addressed params of
     `entry.create`/`create_batch`/`update`/`rotate`/`reveal`/`totp.*`, §4.1b; 15 MCP tools; 24 top-level
     CLI subcommands with `field` and the field selectors; the bridge at 53/53 plus three shell
     commands, every screen wired, §5; durable `node.seal`/`node.restore` and the staged approval,
     §4.1b) — no error code was added (still 25). Updated 2026-10-24 for ADR-083…089 (54 ops:
     `util.generate` built and left the planned list; additive fields and params on existing ops, §4.1c; a
     wholly locked vault records a reveal as `approval_pending`; 26 top-level CLI subcommands with `generate`
     and `approve`; the bridge at 54/54; 15 MCP tools and 25 error codes unchanged). Updated 2026-10-26 for ADR-090/091
     (55 ops: `vault.approval_get` built; `vault.status` gains `pendingApprovals`; the shell passes the envelope's `audit` into the
     answer of every changing op; name-creating answers carry `warnings`; `credmgr approvals`; the bridge at 55/55; 15 MCP tools and 25
     error codes unchanged). -->
# API surfaces — broker protocol, CLI, MCP

`CredMgr V2` · the wire contract, the whole operation surface, and which parts of it exist · `2026-08-18`

> **Status.** The **broker protocol is built** — framing, envelopes, the 26-variant error
> taxonomy, the peer gate and the per-decision audit id all exist in `crates/brokerd/` and are
> covered by the isolation suite. **63 operations are dispatched** (`crates/brokerd/src/ops.rs`);
> since ADR-098 the five that used to refuse because their positive path needs a presence proof (and the
> sealed read) **execute on a Mac with an enrolled Secure Enclave presence key**, and eight new ops carry
> the proof and the Touch ID unlock (§4.2, §4.2a); with no key enrolled they still answer `presence_required`. **The CLI has 24 top-level subcommands**;
> **the MCP server exposes 22 tools** (15, plus `credmgr_notes_read` of ADR-174, plus the six switchboard tools of ADR-155: `credmgr_settings_list/get/set/revert/request` and `credmgr_kb`; the rules, the safety tiers and every setting are in `LLM_KB.md`, generated from `credmgr_core::settings`; since the ADR-155 amendment of 2026-11-21 (wiring audit Q-1) an agent changes only the settings of its own node, the vault's only when its scope is Global, holding `update` there, reads them only while it holds `list`, and never asks for more of its own `agentAccess`). Everything else this document specifies — the other 29
> named operations, the rest of the command surface, two more MCP tools, server-pushed event
> frames, the scripting client, and the full native-shell allowlist — is **`planned`: designed
> here in full, dispatched nowhere.** Section 4 is the honest op-by-op map. `## Source` is where
> every count can be re-derived.

---

## 1. The broker protocol

One process enforces access: `credmgrd`. The CLI, the MCP server, the native shell and any
future scripting client are all **clients of the same socket**, and none of them holds a key or
carries its own idea of what is allowed. That is ADR-001, and this section is the contract that
makes it true rather than aspirational — if a client could reach a secret any other way, the
single-enforcement-point claim would be decoration.

### 1.1 Transport and framing — **`built`**

Newline-delimited JSON over a Unix domain socket at `<vault>/run/broker.sock`, one request per
line, one response line back, one OS thread per connection. The vault directory is resolved by
`crates/store::paths` — `CREDMGR_VAULT_DIR` overrides it; otherwise it is the platform's own
application-data location. The socket is created `0600` inside a `0700` directory, and the
directory mode is owned by the store's atomic helpers rather than by the listener.

There is **no network listener of any kind** (ADR-025, ADR-019). The Windows named-pipe half of
this transport is `planned` — the design is in `16_CROSS_PLATFORM.md`; the current listener is
`UnixListener` and compiles for Unix only.

**Evidence.** `crates/brokerd/src/server.rs` (`run`, `serve_connection`);
`crates/brokerd/tests/isolation.rs` drives `handle_request` directly, and
`crates/cli/tests/broker_integration.rs` drives a real socket end to end.

### 1.2 The request and response envelopes — **`built`**

A request is `{ id, op, token?, params }`. A response is the same `id` plus `ok`, then either a
`value` or a structured `error`. The audit record id is attached by the server, not by the
dispatcher, so every op gets it without remembering to.

```jsonc
// →
{ "id": "1", "op": "entry.reveal", "token": "cmt_…",
  "params": { "node": "northwind", "entry": "e_4f2a" } }

// ←  success. `value` is the op's own object; `audit` names the record this call appended.
{ "id": "1", "ok": true,
  "value": { "node": "northwind", "entry": "e_4f2a", "value": "…" },
  "audit": "a_7c31" }
```

Two details are easy to get wrong and are worth stating plainly. **`value` is the op's whole
response object, not a bare secret** — `entry.reveal` nests its plaintext one level down, and a
client that reads the envelope's `value` as a string will read a JSON object instead. And
**`audit` is best-effort**: writing the record needs the root key, so a locked vault produces a
response with no `audit` field at all. A caller that gets no id has learned less than it could
have, never something false.

### 1.3 The error taxonomy — **`built`**

Denials are typed internally (`OpError`, 26 variants since ADR-098 added `presence_failed`) and become a flat JSON object on the wire
with a short static `error` discriminant. The same discriminant is what the audit record stores,
so a caller's own error and the log's account of it use one vocabulary rather than two.

```jsonc
// ←  needs a second factor
{ "id": "1", "ok": false, "error": "two_factor_required",
  "challenge": "totp", "scope": "global", "expiresIn": 120 }

// ←  vault locked: not a denial — a request the human can approve with one tap (07 §5a)
{ "id": "1", "ok": false, "error": "approval_pending",
  "request": "rq_8f2c", "expiresIn": 120,
  "message": "The vault is locked. The operator has been notified and can approve this single request." }

// ←  the vault is unlocked but this one node is locked (ADR-077): the login is still good
{ "id": "1", "ok": false, "error": "node_locked", "node": "acme",
  "message": "node acme is locked; the vault itself is unlocked",
  "remedy": "unlock this node (vault.node_unlock) and retry - the login is still valid" }

// ←  a concurrent writer moved the node on (F-9)
{ "id": "1", "ok": false, "error": "conflict", "node": "northwind",
  "expectedGeneration": 41, "currentGeneration": 43 }

// ←  denied
{ "id": "1", "ok": false, "error": "node_access_denied",
  "subject": "northwind", "target": "acme", "capability": "reveal", "rule": "R8",
  "message": "Node 'acme' is not readable from node 'northwind'.",
  "remedy": "A human can create a grant: credmgr grant northwind --to acme --scope read --reason \"…\"" }
```

```jsonc
// ←  a Touch ID proof was sent and did not verify (ADR-098)
{ "id": "1", "ok": false, "error": "presence_failed", "operation": "grant.create",
  "reason": "expired", "message": "the presence challenge expired or was already used; ask for a new one" }
```

The twenty-eight variants, grouped by what they tell a caller to do next:

| Class | `error` values | What the caller should do |
|---|---|---|
| Authorisation | `node_access_denied`, `capability_not_held` | Stop and ask a human. `remedy` names the exact command. |
| Authentication in progress | `two_factor_required`, `approval_pending`, `confirmation_required` | Complete the named challenge, or wait for the operator's decision. `confirmation_required` (ADR-150) carries `operation`, `mode` (`window` / `everyTime`) and `windowSeconds`: the vault's "confirm before showing secrets" policy holds the owner's login back until `session.confirm` (Touch ID or the passphrase, §4.2b); the app and the CLI do this themselves, then repeat the request once. An agent is never asked. |
| Authentication failed | `wrong_passphrase`, `gate_verification_failed`, `gate_not_enrolling`, `approval_denied`, `rate_limited` | Do not retry in a loop; `rate_limited` carries `retryAfterSeconds`. |
| Lock state | `vault_locked`, `node_locked`, `machine_lock_refused` | `vault_locked`: the **whole vault** is locked — only `entry.create` is permitted (ADR-023), and `entry.create_batch`, which runs each item through it and holds the whole batch in the pending tray (ADR-073); a client's login is over. `node_locked` (ADR-077): the vault is unlocked but the named `node` (it is in the body) is locked individually — unlock it with `vault.node_unlock`; the login is still valid. `machine_lock_refused` (ADR-165): the passphrase file is sealed to a device key this Mac does not hold, or is damaged (`reason`: `device_key_missing`, `device_key_mismatch`, `device_key_unreadable`, `sealed_wrap_damaged`, `device_key_unwritable`), or (`plain_wrap_while_bound`, review P0-1) this Mac bound the vault and an older plain passphrase file that no longer opens it was put back; it is not a wrong passphrase and does not count in the back-off. `remedy` names the recovery code (`credmgr recover`, the Lock screen's "Forgot passphrase?"). |
| Session ended (ADR-068) | `session_expired` | The token presented is not a live login — it idled out, the vault locked, or it never existed. Unlock again; do not retry with the same token. |
| Presence | `presence_required`, `presence_failed` | `presence_required`: the operation needs a Touch ID proof — ask `presence.challenge`, have the Secure Enclave sign, repeat with `params.presence` (the CLI and the desktop shell do this themselves); with no key enrolled there is nothing to complete (enrol one, §4.2a). `presence_failed` (ADR-098) carries a `reason`: `not_enrolled`, `expired`, `invalid`, `cancelled`, `locked_out`, `unavailable`. An agent or fixture token can never hold a proof. See §4.2. |
| Concurrency | `conflict` | Re-read, re-apply, retry once with the current `generation`. |
| Data state | `not_found`, `entry_exists`, `archive_expired`, `entry_removal_expired`, `not_undoable` | A terminal answer about the vault's contents, not about permission. |
| Vault bootstrap (ADR-061) | `vault_already_initialized`, `vault_inside_git_working_tree`, `vault_init_not_pending`, `recovery_code_mismatch` | A terminal answer about `credmgr init`'s state — a vault already exists, the path is inside a git working tree, no init is pending, or the retyped recovery code did not match. `vault.recover` (ADR-163) answers `recovery_code_mismatch` for a recovery code that does not open the vault, and there it counts in the unlock back-off. |
| Caller error | `malformed_request` | Fix the request. |
| Broker fault | `internal` | A local failure outside the documented taxonomy. |

`gate_verification_failed` is deliberately undifferentiated: it covers a wrong code, a replayed
TOTP step, an expired challenge and an already-consumed recovery code with one answer, because
telling a caller *which* check failed is a side channel (`07 §5`).

**Evidence.** `crates/brokerd/src/protocol.rs` — the enum and its single `to_wire` mapping;
`crates/brokerd/src/server.rs::error_tag` matches the enum exhaustively, so a new variant is a
compile error rather than a silently generic audit line.

### 1.4 Invariants the transport enforces

Each of these is a property of the socket layer rather than of any one operation, so no op can
opt out of it. Their statuses differ, and pretending otherwise is exactly the defect this rewrite
removes.

| Invariant | Status | Evidence / what is missing |
|---|---|---|
| A peer whose uid is not the vault owner has its connection closed before the first frame is read | **`built`** | `server.rs::serve_connection` calls `peer::identify_peer` then `peer_is_owner` before constructing a reader |
| Every request either carries a token or is resolved from the caller's cwd to a minimum scope | **`built`** | `scope.rs::resolve_scope`; I-11 proves a cwd-scoped caller cannot reach another node under any argument |
| A request that presents a token the broker does not hold is refused as `session_expired`, never resolved from cwd — except `vault.status`/`unlock`/`gate_verify`/`gate_recover`/`recover` (ADR-163)/`init_begin`/`init_confirm`/`lock` | **`built`** (ADR-068) | `server.rs::handle_request_at`, `TOKENLESS_OK_OPS`; `session_login.rs::a_token_the_broker_never_issued_is_refused_not_resolved_from_cwd` |
| A session token appears only in the response of the op that mints it (`vault.unlock`, `vault.gate_verify`) — never in the audit log, an `audit.tail`/`audit.get` response, a log line, an error or a `Debug` print; the audit `actor` is `<Origin>` or `<Origin>:s_<16 hex>` | **`built`** (ADR-077) | `server.rs::audit_actor`/`scrubbed`, `token.rs::redact_bearer_tokens`; `audit_actor.rs` (4 tests); the endpoint matrix's all-secrets plaintext invariant and its `audit.tail` rows judge the bytes. Alpha vaults written before this still hold dead `cmt_…` strings in their audit files — `v2/SECURITY.md` |
| A token's scope is fixed at issue and cannot be raised at runtime | **`built`** | `token.rs` exposes no mutator for `node_id`/`capabilities`; `BrokerScope::holds` is a ceiling checked *in addition to* `resolve()` |
| A token presented from a cwd that disagrees with its `boundWorkdir` proceeds, and writes an anomaly record | **`built`** | I-12; `server.rs::record_anomaly` — the anomaly never blocks the request that raised it |
| `grant.create` and `node.reparent` refuse every origin that cannot prove live presence | **`built`** (ADR-098) | both arms require a verified presence proof — a Secure Enclave signature over the exact params, single-use, bound to the session — and otherwise answer `PresenceRequired`; an agent or fixture token can never hold one; I-23 for `reparent`, `crates/brokerd/tests/presence.rs`. `grant.create` also needs a fresh vault second factor when one is enrolled, asked before the proof (`two_factor_required`, ADR-174); `crates/brokerd/tests/grant_ops.rs` |
| Values appear only in `entry.reveal` and `totp.code` responses — never in list, get, search, audit or event frames | **`built`** | `ops.rs` returns a plaintext in exactly those two arms; `entry.get` (ADR-078) returns field ids, labels, types and masking and **no value**; the audit module's own contract is that it never records a value or a label |
| Every request that mutates an *existing* entry carries the caller's last-seen `generation`; a stale value returns `conflict` rather than overwriting, and writes are serialised per node | **`built`** | `entry.update`/`rotate`/`remove`/`restore`/`undo` and the four `field.*` ops all require `params.generation` (each of those arms in `ops.rs` reads `params["generation"]`); `state.node_write_lock` serialises; I-25 proves exactly one of two concurrent writers wins. **`entry.create` is the exception, not covered by this row** — it bumps `generation` but reads no `params.generation` (its `ops.rs` arm), because there is nothing yet to conflict with — nor, for the same reason, `entry.create_batch` (`ADR-073`). `notes.write` requires `params.generation` too (`ADR-072`) |
| `entry.create` is permitted while locked (into the pending tray); `entry.update` is not | **`built`** | I-18; ADR-023 |
| Every decision, allow or deny, appends one audit record and returns its id | **`partial`** | `server.rs::record_decision` does this generically for every op — but it needs the root key, so a locked vault silently appends nothing |
| The passphrase presented at `vault.unlock` is verified against the keystore on that request | **`built`** since 2026-09-24 (ADR-063) | `vault.unlock {passphrase}` builds a request-scoped `Software` keystore from it, proves it against `keys/root.wrap.pass`, and loads and verifies the vault from disk (`crates/brokerd/src/state/durable.rs`); a passphrase-less `vault.unlock` is refused on any disk-backed vault. `crates/brokerd/tests/durable_vault.rs` |

That last row was, until 2026-09-24, the single most important honest correction in this
section: the unlock flow unwrapped the root key, honoured the 2FA gate, minted a session token
(ADR-056) and tripped the uid-keyed backoff on failure (ADR-044) — but ignored
`params.passphrase` and unwrapped with the keystore the broker built at start-up, so it proved
the *process* had the key, not that the *caller* knew the passphrase, and a real daemon answered
`wrong_passphrase` to the right one. ADR-063 closed it: the caller's passphrase is now the first
factor, the passphrase keystore is dropped at once, and the root key stays resident until lock
(`04_CRYPTO_AND_KEYS.md §6`).

### 1.5 Server-pushed event frames — **`planned`**

**Nothing pushes an unsolicited frame today.** `serve_connection` writes exactly one response
line per request line and never writes on its own initiative; there is no subscriber set, no
event type and no `"event"` string anywhere in `crates/brokerd/`. A previous version of this
document said the broker "may also push unsolicited `event` frames (lock, anomaly, expiry)" in
the present tense, and nothing implemented it.

The target design. The broker **will** be able to write a second frame kind on an already-open
connection, distinguished by carrying `event` instead of `id`:

```jsonc
{ "event": "vault.locked", "reason": "idle_timeout", "at": 1755500000 }
```

Four event kinds **will** be defined, chosen because each one is a state change a client cannot
learn by polling without either racing or leaking:

- **`vault.locked`** / **`vault.unlocked`**, with a `reason` of `idle_timeout`, `explicit`,
  `external_signal` or `unlock`. The idle half already exists as a timer inside the broker
  (ADR-043); today a client discovers the transition only by making a request and being refused.
- **`node.locked`** / **`node.unlocked`**, for the per-node timers (F-7, ADR-030).
- **`approval.requested`** and **`approval.decided`**, so that the native shell will be able to raise
  the one-tap approval prompt (F-15, `07 §5a`) rather than the operator discovering a blocked
  agent later.
- **`anomaly.raised`**, carrying the same kind the audit record already stores.

Three rules **will** bind every event frame, and they are the reason this is a design decision
rather than a plumbing detail. An event **will never carry a value, an entry name, or a node the
receiving connection could not already `list`** — the frame is a notification, and a
notification channel that leaks topology would undo `whoami`'s reachability filter. An event
**will be fire-and-forget**: a client that is not reading gets frames dropped, never a broker
that blocks. And **no event will ever be a substitute for a check** — a client that acts on
`vault.unlocked` without making a request is trusting a cached state that may already be stale.

## 2. CLI

Backwards-compatible with V1 where it can be, explicitly broken where V1 was wrong. One binary,
which is also the MCP server (`credmgr mcp`) and therefore one artefact to sign and one to trust
(`16 §2`).

### 2.1 The built command surface — **`built`, 24 top-level subcommands**

```bash
credmgr init                            # first-run vault creation; passphrase from stdin,
                                        # prints the recovery code once (ADR-061)
credmgr status [--ack | --log]          # --log: where the diagnostic log is, without asking the
                                        # broker (ADR-159)
credmgr unlock                          # passphrase from stdin; prints `export CREDMGR_TOKEN=…`
credmgr gate verify [--code-on-argv <n>]
                                        # completes an unlock that returned two_factor_required; the
                                        # authenticator code is typed at a prompt or read from stdin,
                                        # never an argument (ADR-113)
credmgr gate enroll                     # turns on two-factor; prints the otpauth:// URI, then the
                                        # ten recovery codes once (ADR-064)
credmgr gate recover                    # lost authenticator: passphrase + root recovery code,
                                        # both from stdin, reset the gate; never unlocks (ADR-064)
credmgr recover [--json]                # forgotten passphrase: the root recovery code, then a new
                                        # passphrase (and a second-factor code if one is enrolled),
                                        # from stdin; opens the vault, sets the new passphrase and
                                        # prints a NEW recovery code once - the used one is retired (ADR-163)
credmgr lock
credmgr whoami [--json]
credmgr list [--node <id>] [--json]
credmgr get <name> [--node <id>] [--field <label> | --field-id <id> | --all] [--json]
                                        # one value; an entry with several fields needs a selector
                                        # (exit 2 lists the labels); `--json` prints the fields (ADR-078)
credmgr field ls <name> [--node <id>] [--json]
                                        # labels, types, masking and ids — never a value
credmgr field add <name> --label <l> [--node <id>] [--bulk] [--at <n>]
                                        # value(s) from stdin; `--bulk` appends many
credmgr field set <name> (--field <l> | --field-id <id>) [--label <new>] [--type <t>|auto]
                  [--mask on|off|auto]  # metadata only: the value goes through `set --field`
credmgr field rm <name> (--field <l> | --field-id <id>)   # undoable: prints the audit id
credmgr field mv <name> (--field <l> | --field-id <id>) --to <n>
credmgr search <term> [--json]
credmgr search <term> --deep [--node <id>] [--json]     # ADR-132: inside field VALUES; node and name only
credmgr node rekey <id>                 # ADR-130: new node key, every file re-sealed; fresh code + Touch ID
credmgr orphan ls [--json]              # sealed entries: names only
credmgr orphan destroy (--all | <entry-id>...) --count <n> --confirm destroy-sealed-entries   # ADR-131: for good
credmgr export --node <id> --out <file> --age [--age-recipient <age1…>]... [--force]
                                        # ADR-133: age file, mode 0600, never stdout; passphrase from stdin twice
credmgr audit report (--days <n> | --from YYYY-MM-DD --to YYYY-MM-DD) [--node <id>] [--json]   # ADR-134
credmgr gate enroll|verify|remove [--last-door] --node <id>  # verify reads the code from a prompt or stdin   # ADR-135: a project's own second factor
credmgr set <name> --node <id> [--bulk] [--field <l> | --field-id <id>] [--label <l>]
                                        # value from stdin; `--bulk` parses the paste locally into
                                        # ONE multi-field entry; `--field` replaces one field
credmgr rotate <name> [--node <id>] [--field <l> | --field-id <id>]
                                        # new value from stdin, keeps history
credmgr rm <name> [--node <id>]         # soft, 7-day recovery
credmgr undo <id> --node <id> [--mode replace|keep-both]
credmgr audit [--limit N] [--json]
credmgr verify [--json]                 # also hashes every envelope against its manifest digest (ADR-067)
credmgr pending [--node <id>] [--json]  # the locked-write review tray; no --node lists every node (ADR-069)
credmgr pending accept|discard <entry> --node <id>
credmgr doctor [--dry-run]
credmgr backup [--retain N]             # a COMPLETE encrypted archive (ADR-112); passphrase from stdin
credmgr restore <archive> [--to <empty dir>] [--state-dir <dir>]
                                        # rebuilds a vault from a backup archive; offline, backup
                                        # passphrase from stdin, refuses a target that is not empty (ADR-112)
credmgr approve <request> [--deny] [--code-on-argv <n>]
                                        # passphrase = first stdin line; authenticator code = second
                                        # line, or asked for at a terminal (ADR-113)
credmgr import <file|-> --node <id> [--format json|env] [--json]
                                        # a .env-style file becomes entries in ONE all-or-nothing
                                        # entry.create_batch call (ADR-073); `-` reads stdin; values
                                        # are never printed; empty values are skipped and named.
                                        # rc.2: a .json file (or --format json) is an array of
                                        # {"name","value"} or {"name","fields":[{"label","value","type"?}]}
                                        # items, passed to the same call as they are; same 500 ceiling
credmgr notes show <id> [--json]        # the node's markdown note (ADR-072)
credmgr notes set <id> [--file <path>]  # text from the file or stdin; EMPTY input is refused
credmgr notes clear <id>                # the only way to delete a note
credmgr node ls | create <id> --label <l> --parent <p> [--workdir <dir>]... | seal <name> | restore <name>
credmgr node workdir <id> [<dir>...]    # binds directories: an agent run inside is scoped to <id>
                                        # (ADR-066); no <dir> clears the list
credmgr node rename <id> <label>        # the display name only; the id never changes (ADR-071)
credmgr node policy <id> --reason "…" [--agent-access read-write|read-only|none]
        [--require-two-factor never|reveal|always] [--lock-after-seconds <n>|none]
        [--private-names|--no-private-names] [--sibling-visibility shared|isolated]
        [--descendant-read|--no-descendant-read] [--json]
                                        # a partial patch, all-or-nothing; a change that widens
                                        # reach is refused with presence_required (ADR-071)
credmgr grant <from> --to <node> [--entry <id>] --scope read --reason "…" [--expires-in-days <n>]
                                        # Touch ID, and a fresh authenticator code when the vault has
                                        # one; a one-entry grant expires (30 days unless given, 90 at
                                        # most; ADR-174)  | grant ls | grant revoke <id>
credmgr mcp                             # the MCP stdio server; for agent config, not humans;
                                        # presents CREDMGR_AGENT_TOKEN if set, never CREDMGR_TOKEN
credmgr agent token issue <node> --label "…" --cap list,read [--expires 8h]
                                        # a node-scoped agent token, shown once on stdout;
                                        # owner login, second factor, Touch ID (ADR-164)
credmgr agent token ls [--node <id>] | rotate <id> [--expires …] | revoke <id>
credmgr --version                       # version, commit, dirty flag and platform
```

Counting every nested subcommand arm as its own command — `node`'s 7 (`create`/`workdir`/`rename`/
`policy`/`ls`/`seal`/`restore`), `grant`'s 2 (`ls`/`revoke`), `gate`'s 3 (`verify`/`enroll`/`recover`),
`pending`'s 3 (`list`/`accept`/`discard`), `notes`' 3 (`show`/`set`/`clear`) and `field`'s 5
(`ls`/`add`/`set`/`rm`/`mv`) — gives 47, not 24 (41 until 2026-10-03, when `field` landed; 34 until
2026-10-02, when `import`, `notes` and `node rename`/`policy` landed; 27 until 2026-09-24), which is how an
earlier count in this corpus was wrong. The dispatch table in `crates/cli/src/main.rs::run` has 24
top-level arms plus `help` and `--version`.

**Several fields (ADR-078).** An entry made by `set --bulk` holds one field per `label: value` line (or per
`///` block, `08 §3`); the CLI parses it with `credmgr_core::parser` — the same code the desktop preview
runs — and sends the structure, because the broker does not parse the grammar. `get` on such an entry with
no selector exits **2** and lists the labels rather than guessing — built so today that the CLI first sends an
`entry.reveal` for the whole entry (one audited reveal, values held in the CLI process, none printed), where it should
list the labels from `entry.get` and reveal nothing; see `CHANGELOG.md` known issues. The same exit status means "name the
field" for a label that matches none or two (`--field-id` is the exact form). `--all` prints `label: value`
lines, a multi-line value as a `///` block.

`notes set` never deletes: an empty or whitespace-only input is refused and nothing is sent, so a
failed upstream pipe (`failing-cmd | credmgr notes set acme`) cannot destroy a sealed note;
`notes clear` is the only deletion, and a no-op with a message when there is no note. Both take the
manifest generation from `notes.read` (ADR-077), so a grantee holding `notes` without `list` can
write. `import` reads a `.env`-style file — `NAME=value` lines, `#` comments, `export`, quotes. A
quoted value is closed by the next matching quote; a missing closing quote is detected when the value
would swallow a line that starts like `NAME=…` and is **refused**, naming the two line numbers and
never the content; otherwise the file is read as written. To keep an assignment-shaped line inside a
value, write it on one line with `\n` escapes in double quotes. A batch that stops part-way
(`complete: false`) exits non-zero; with nothing saved the message says "nothing was saved". `--reason`
on `node policy` and `grant` refuses an option (anything starting `--`) where the reason text belongs,
rather than recording it as the reason.

`credmgr unlock` is a real login: on success it prints an `export CREDMGR_TOKEN=…` line, and the
token is presented on every subsequent request through the environment — never as a flag, for
exactly the reason a value is never a flag. Since ADR-065 that login reaches every project in the
vault, so the CLI prints a `#` warning line beside it (ignored by `eval`) to keep it out of any
shell an AI agent runs in — K-6, closed by ADR-174 for an unlock made inside a project's folder (that login reaches
that project only and works only from its folder; the warning stays for the owner's own login). `credmgr grant <from> --to …` is wired end to end and
validates every parameter (since ADR-174 a vault with a second factor answers `two_factor_required` first, and
the CLI says to give the code with `credmgr gate verify`), and then asks for Touch ID itself (the CLI answers `presence_required` with a
challenge, a signature and a retry) — or, with no presence key enrolled, refuses and says to run
`credmgr presence enrol` (ADR-098, §4.2).

### 2.2 A secret never travels in argv — **`built`, structurally**

No subcommand defines a flag or positional that carries a secret. (A field's *label* and id, a position and
a type are naming, not secrets, and may be flags: `--field`, `--field-id`, `--label`, `--at`, `--to`, `--type`,
`--mask`; the test's allowlist names every flag.) New and updated values, the
unlock passphrase, and `gate recover`'s passphrase and root recovery code are read from stdin
only; `import` and `notes set` take their text from a file or stdin only. There is no exception left (ADR-113, issue #39): an authenticator code is a single-use number, but a
same-user process sees argv in `ps`, so `credmgr gate verify` and `credmgr approve` read it from a
prompt or stdin. `--code-on-argv <n>` keeps the argument for the few places that cannot prompt, and
`credmgr help` says what it costs; the old spelling `gate verify <code>` is refused without sending
anything.

This is asserted by a test that inspects the argument surface itself rather than by review —
`crates/cli/tests/no_secret_in_argv.rs`. That matters because the failure mode is a future
session adding one convenient flag.

### 2.3 The planned command surface — **`planned`**

The commands below are designed and mapped in `18_ENDPOINT_INDEX.md §2`; none of them is
dispatched today. (`import`, `notes show`/`set`/`clear` and `node rename`/`policy` left this table on
2026-10-02 and are in §2.1; `history` and `expiring` left it on 2026-11-09 with `ADR-156`, which built them
with `passphrase`, `expire` and `ref` — see `18_ENDPOINT_INDEX.md §1` for each op behind them.) They are grouped by the op namespace each one **will** call, so the CLI's
missing surface and the broker's missing surface (§4.3) stay one list rather than two.

| Command | Will call | Notes on the target behaviour |
|---|---|---|
| `credmgr export --node <n> --out <file>` | `node.export` | Will require 2FA, presence and an explicit `--out`. Will never write to stdout. |
| `credmgr env --node <n>` | `node.export` | Will emit `KEY=value` lines to a file, never to a terminal. |
| `credmgr batch --node <n>` | `entry.create_batch` | Will open `$EDITOR` and create several entries from one paste, one per `///` block. The op takes multi-field items since `ADR-078`; `credmgr import` is the only command that calls it today. |
| `credmgr generate [--length N] [--no-symbols] [--pronounceable \| --hex] [--copy \| --json]` | `util.generate` | **Built** (ADR-087): the password alone on stdout, its strength on stderr. `--hex` (rc.2) makes lower-case hex. `--copy` (rc.2, macOS) puts it on the clipboard instead of stdout via `pbcopy` and clears it after 30 s only if the clipboard still holds it; `credmgr get --copy` and `credmgr totp --copy` do the same. |
| `credmgr totp <name> [--node <id>] [--field <label> \| --field-id <id>] [--copy \| --json]` | `totp.code` | **Built** (rc.2): the current code alone on stdout, never the seed; the seconds it stays valid (`validForSeconds`, 1–30) on stderr, or in `--json`. |
| `credmgr node rm` / `reparent` | `node.seal`/`node.reparent` | `seal` and `restore` exist as `credmgr node seal` / `credmgr node restore`, `policy` and a rename as `credmgr node policy` / `credmgr node rename` (§2.1); `credmgr node reparent` exists since ADR-098 and asks for Touch ID itself (§4.2). |
| `credmgr pending ls` / `accept` / `discard` | `vault.pending_*` | **Built since 2026-09-24** (`ADR-069`) as `credmgr pending` — §2.1. Kept in this table only because it predates the command; it said no command reached the three ops. |
| `credmgr audit --purge` | `audit.purge` | Will be human-only and 2FA-gated, and will never be reachable from an agent transport. |
| `credmgr scan` | `entry.*` | Will scan a work folder for credential-shaped files and offer to adopt them into the node. |
| `credmgr mcp --print-config [<client>]` | — | **Built** (ADR-141): the exact MCP configuration for `claude-code`, `claude-desktop`, `cursor`, `vscode`, `windsurf`, or generic JSON, on stdout. No file read or written, no server started. |
| `credmgr agent detect` / `connect` / `disconnect` / `init` | — (no broker op, ADR-146) | **Built** (ADR-142, ADR-143): finds the clients, shows the diff and writes only the `credmgr` entry on `--yes` or a typed `y` (backup first, never Claude Code's `~/.claude.json`); `init` writes `CREDMGR.md` into a work folder. |
| `credmgr prompt [--node <id>]` | `whoami` / `graph.snapshot` | **Built** (ADR-143): the Vault Protocol prompt (`17 §5`) from the live vault, names and structure only. |
| `credmgr token issue` / `rotate` / `revoke` | `agent.token_*` | **Built** (ADR-164) as `credmgr agent token issue <node> --label … --cap …` / `ls` / `rotate <id>` / `revoke <id>` — subcommands of `agent`, not a top-level `token`. Owner login only; `issue` and `rotate` ask for the second factor where enrolled and Touch ID; the token alone on stdout (§4.2e). |
| `credmgr keystore status` / `bind` / `unbind` | `keystore.*` | **Built** (ADR-165, the smallest safe version ADR-144 defined): the machine lock, macOS file tier only. `status` prints the honest tier (a device key file on this Mac, never the Secure Enclave), what it protects and what it does not; `bind` asks for the passphrase and the current recovery code, rotates the root key, re-keys every project, seals `root.wrap.pass` and prints the NEW recovery code once (`RECOVERY_CODE=`); `unbind` asks for the second factor and Touch ID where they are on, and the passphrase where neither is. `credmgr recover` and `credmgr passphrase` print whether the machine lock is still on, and warn when the rotation removed it. `--json` on each. Kept in this table only because it predates the command (§4.2d). |
| `credmgr ssh-agent-add <name>` | `entry.reveal` | Will load a key into the running SSH agent and never write it to disk. |
| `credmgr which` / `where` / `home` | — | Will print the resolved vault, socket and binary paths for support purposes. |

### 2.4 Removed from V1, deliberately

| V1 | Why it is gone |
|---|---|
| `credmgr set NAME "value"` (value in argv) | Shell history, `ps` output, process listings. Values come from stdin or `$EDITOR`, always. |
| `credmgr export <project>` writing to stdout by default | Now requires `--node`, 2FA, and an explicit `--out` path. Piping a vault to a terminal is how secrets end up in scrollback. |
| `credmgr ssh-key` writing a temporary plaintext key | Replaced by `credmgr ssh-agent-add`, which loads the key into the agent and never touches disk. |
| implicit project inference from the entry name | Node placement is explicit (`01 §6`). A boundary that is guessed is not a boundary. |
| `credmgr deploy` | V1's deploy embedded one user's server layout. A vault should not own a deploy pipeline. |
| `credmgr migrate` | **There is no migration and no `migrate-v1` command.** V2 ships empty (`11_MIGRATION.md §1`). A previous version of this document showed `credmgr migrate-v1 --from <v1-vault> --dry-run`, which contradicted the decision recorded in `11` and was never implemented. |

## 3. MCP server — the agent surface

One process per agent session, launched by the agent client, scope resolved from its cwd unless a
token overrides (`06 §4`). This is the surface the whole isolation design exists to constrain: an
LLM reaches this vault here or not at all (`17 §1`).

The server speaks JSON-RPC 2.0 over stdin/stdout and implements exactly three methods —
`initialize`, `tools/list`, `tools/call`. No resources, no prompts, no sampling: `credmgr` has
nothing to offer any of those capabilities, and a capability advertised but unimplemented is a
surface an agent will probe. A tool failing is an MCP *tool* error (`isError: true` inside a
normal result), never a protocol-level error — a denied read is a fact about the vault, not a
malformed call. **`built`**: `crates/mcp/src/server.rs`, with the protocol loop tested over
in-memory buffers and `crates/cli/tests/mcp_integration.rs` spawning the real subprocess against
a real broker.

### 3.1 Tools

Fifteen tools are registered. Two more are specified here and are not.

| Tool | Status | Op | Capability | Notes |
|---|---|---|---|---|
| `credmgr_whoami` | **`built`** | `whoami` | — | Returns the caller's node, its capabilities, and the nodes it can reach. An agent should call this first and reason about its own boundary instead of discovering it by being denied. **[Pass 2 · F-6] It returns *only* reachable nodes** — nodes outside scope are not named, not counted, and their existence is not implied. The naive implementation (list everything, flag reachability) would hand an agent every project name on the machine, which is most of the reconnaissance value the isolation model exists to withhold. I-22. |
| `credmgr_list` | **`built`** | `entry.list` | `list` | Entry names and ids for one node. Scope-filtered; never returns another node's entries. `node` is required (the schema said optional until 2026-09-24 — §3.1a). An agent caller gets `node`, `ids`, `names`, `generation` and, **only when some listed entry carries tags, a `tags` map `{<entry id>: [...]}`** (ADR-174, decision 1; never another node's, never on a `privateNames` node): the `entries` metadata of §4.1a is otherwise for human sessions only (ADR-077). |
| `credmgr_search` | **`built`** | `search` | `list` | Substring match over entry *names* only, across every node the caller can reach. A term matching only out of scope returns the identical empty result as a term matching nothing (I-3). Takes `term` (it advertised `query` until 2026-09-24 — §3.1a). |
| `credmgr_get` | **`built`** | `entry.reveal` | `reveal` | The value. Subject to the node's 2FA policy and the vault's lock state. Takes `fieldIds` to narrow to some fields and answers `fields` (plus `value` when exactly one field is returned) — ADR-078. |
| `credmgr_get_metadata` | **`built`** | `entry.get` | `read` | One entry's field ids, labels, types and masking, **never a value** (ADR-078). Needs the node unlocked, because labels are encrypted with the values. A read-only agent holds it. |
| `credmgr_create` | **`built`** | `entry.create` | `create` | A **new** entry: `value` (and `label`) or a structured `fields` array — the broker does not parse `label: value` text, agents send structure. Works on a locked vault; lands in the pending tray for human review at unlock. |
| `credmgr_update` | **`built`** | `entry.update` | `update` | Modifies an existing entry; `field` addresses one field, `fields` replaces the list. **Requires the vault unlocked** — see `04 §3` on credential substitution. |
| `credmgr_rotate` | **`built`** | `entry.rotate` | `update` | Preserves the previous ciphertext as history. Same body as update, same unlock gate: a legitimate rotation implies the caller could have read what it is replacing. |
| `credmgr_field_add` | **`built`** | `field.add` | `update` | Appends (or inserts at `position`) fields to an entry; keeps history, undoable (ADR-078 D11). |
| `credmgr_field_update` | **`built`** | `field.update` | `update` | Changes one field's label, value, type or masking (`"auto"` clears a pin); keeps history. |
| `credmgr_field_remove` | **`built`** | `field.remove` | `update` | Removes one field (never the last); keeps history, so `credmgr_undo` puts it back. |
| `credmgr_remove` | **`built`** | `entry.remove` | `update` | Soft, into a 7-day recovery window. |
| `credmgr_undo` | **`built`** | `entry.undo` | `update` | Undoes a rotate or a removal, addressed by its audit record id — never by guessing at what changed. `keep-both` collision mode retained from V1. Itself a new audited action; the original record is never rewritten (ADR-055). |
| `credmgr_totp_code` | **`built`** | `totp.code` | `reveal` | **The six digits only.** Takes `field` when the entry holds several seeds. |
| `credmgr_recent_changes` | **`built`** | `audit.tail` | `list` | Redacted feed — id, action, timestamp, actor. The redaction is a property of the op for an agent origin, not a courtesy of this tool. `actor` names the origin and, for a live session, its public id (`HumanUi:s_…`) — never the token (ADR-077). |
| `credmgr_notes_read` | **`built`** (ADR-174) | `notes.read` | `read` | **Read-only, own node only.** An agent reads the note of the project it is scoped to under its own `read` capability (the `notes` capability stays out of an agent's reach); any other node is refused with nothing said of it. A note follows the **high-sensitivity reveal rules** (ADR-156): a **Guarded or Strict** node does not hand its note to an agent (a high value's reveal waits for the owner there and a note has no approval path), so only an **Open** node does, and the node's second factor is asked as for a reveal; a `privateNames` node answers that a note exists and none of it. The tool's description labels the note **untrusted user content**. |
| `credmgr_notes_write` | **never** | `notes.write` | `notes` | Not registered and not to be: notes are the owner's. `notes.write` needs `notes`, which an agent never holds, and I-13 asserts no tool maps to it. |

There is no tool for `field.reorder`: ordering is presentation only, and an agent has no use for it
(`FORBIDDEN_OPS` is unchanged; the three field writes are no wider than `credmgr_update` and
`credmgr_remove`, which an agent already holds). I-13 pins the registry to exactly this reviewed set
(22 tools since ADR-174), so another cannot appear without a reviewed change.

Every registered tool is a thin, verbatim forwarder: `call_tool` looks the name up, forwards
`arguments` to the named op unchanged, and unwraps the envelope. There is no tool-specific logic,
because the broker is the enforcement point and a tool that reshaped a response would become a
second place where the truth about a denial lives.

### 3.1a Two schema defects found in this pass — **`built`** (fixed 2026-09-24)

**Fixed 2026-09-24** (gap G-14, found in the Session 27 review): `credmgr_search` now takes `term`,
`credmgr_list` requires `node`, and `credmgr_update` advertises the optional `label` its op already
read. The gap this section named — nothing mechanical compared a tool's schema with its op — is
closed by `crates/mcp/tests/schemas_match_the_broker.rs`, which reads `ops.rs` off disk and fails
if a tool advertises a key its arm never reads, omits one the arm reads, or marks optional one the
arm refuses without. The record below is the finding as it stood.

Two registered tools declared an input schema the broker op behind them does not implement. Both
were found by reading `tools.rs` against `ops.rs` on 2026-08-18; neither is recorded in
`PHASE8_AUDIT_REPORT.md`, `BUILD_LOG.md` or any test.

- **`credmgr_search` declares a required `query` parameter. The `search` op requires
  `params.term`.** Arguments are forwarded verbatim, so an agent that follows the advertised
  schema receives `malformed_request` every time. The CLI passes `term` and works, which is why
  the defect is invisible from the human surface.
- **`credmgr_list` declares `node` as optional ("Omit to use the caller's own scope"). The
  `entry.list` op requires `params.node`.** Omitting it returns `malformed_request` rather than
  listing the caller's own node.

Neither is a security defect — both fail closed, and no denial is bypassed. Both are availability
defects in the surface an agent is told to trust, and both are one-line fixes in
`crates/mcp/src/tools.rs`. The reason they survived is structural and worth recording: the
end-to-end MCP test file (`crates/cli/tests/mcp_integration.rs`) covers `credmgr_get`,
`credmgr_totp_code`, `credmgr_rotate`, `credmgr_remove`, `credmgr_recent_changes`, `credmgr_list`
and a cross-node denial. **Five tools it does not exercise: `credmgr_whoami`, `credmgr_search`,
`credmgr_create`, `credmgr_update`, `credmgr_undo`.** Two of those five are exercised elsewhere —
`credmgr_whoami` and `credmgr_create` appear in `crates/cli/tests/success_criteria.rs` — so
**three tools are never reached by a `tools/call` anywhere in this workspace: `credmgr_search`,
`credmgr_update` and `credmgr_undo`.** Only `credmgr_search`'s absence is explained by a schema
defect — the one this section opened with. `credmgr_update` and `credmgr_undo` carry no known
schema defect; they are simply untested, a plain test-coverage gap rather than an instance of
either defect above. I-13 walks the same registry and would not catch any of this: it asserts what
a tool must never do, not that a tool works.

**The fix, when it is made, should not be only the two-line rename.** The durable form is a test
that walks `registry()` and asserts, for every tool, that a call built from its own declared
schema reaches the broker without a `malformed_request` — a registry-wide property, so the next
tool added cannot reintroduce the same class of defect. That test does not exist and this
document does not claim it does.

### 3.2 Tools that must never exist

This list is normative. It is restated in code as `credmgr_mcp::tools::FORBIDDEN_OPS`, kept
beside the registry rather than in a test file so the two stay visibly in sync, and enforced by
**I-13** (`crates/mcp/tests/i13_tool_registry.rs`) in two independent directions: no registered
tool may map to a forbidden *op*, and no tool *name* may contain a forbidden fragment. Either
check alone would miss a tool that calls a permitted op under a misleading name, or the reverse.
**Since the 2026-11-20 wiring audit (Q-3) the list is complete by construction:** `FORBIDDEN_OPS`
names every op `docs/help/ops.json` classes `human_only` (the owner's login, `admin`, the `notes`
capability or presence; refused to every agent scope), and I-13's
`the_forbidden_list_names_every_human_only_op` fails when a human-only op is missing from it — so a
new owner-only op is guarded the day it is dispatched, not when someone remembers to list it. The
bullets below are the reasons; the code list is the whole set.

- **No grant creation or modification.** `Grant.createdBy` is typed `'human'`; there is no agent
  path, and adding one would defeat the entire access graph.
- **No orphan read.** Not gated — absent. `orphan.list` and `orphan.reveal` (ADR-098) have no MCP tool and
  no CLI command; the broker refuses everything but the owner's own session with a fresh second factor and a
  Touch ID proof, whatever any tool asks.
- **No TOTP seed.** `credmgr_totp_code` returns a code worth thirty seconds; a seed is worth
  forever. The `totp.seed` op exists in the broker; it runs only for the owner's login with a
  Touch ID proof (ADR-098), and for every agent or MCP scope it returns `presence_required` and nothing else.
- **No node policy or `agentAccess` change, and no rename.** An agent may not widen its own scope.
  This is the definition of the boundary. Since `ADR-071` the list names the real ops,
  `node.policy` and `node.update`, beside the two placeholder names (`node.policy_update`,
  `node.agent_access_update`) that predate them; both ops also refuse `Origin::Agent` in the
  broker itself.
- **No node re-parenting.** [Pass 2 · F-8] Moving a node changes its ancestor set and therefore
  what it can read — a grant by another name. Human and presence only (a Touch ID proof, ADR-098).
- **No listing of nodes outside scope.** `credmgr_whoami` names only reachable nodes; nothing
  else enumerates the vault's topology.
- **No audit purge, no recovery-window shortening, no `forcePurge`.** The 7-day recovery window
  and the hash-chained log cannot be erased by anything that runs unattended. (The audit log's
  own retention is twelve months and is a separate mechanism — `03_DATA_MODEL.md §9`.)
- **No cross-node read of any kind, under any parameter.** There is no `--node` override, no
  `all: true`, no `includeInherited`.
- **No raw envelope, key, or file-path access.**
- **No vault-wide maintenance.** `maintenance.verify|doctor|backup` are on the forbidden list
  (ADR-054): `doctor` and `backup` mutate vault-wide state, and `verify`'s errors can name a
  security-relevant condition — a tampered manifest — that belongs in front of a human, not
  silently in an agent's context.
- **No tidy-up scan.** `vault.doctor_scan` (ADR-161) compares values across every node the owner can
  read; even its counts would map the vault for whoever ran it. It is on `FORBIDDEN_OPS`, and the broker
  answers only the owner's login (`capability_not_held` to every agent scope).
- **No merge.** The eight `merge.*` ops (ADR-168) are on `FORBIDDEN_OPS`: a suggestion of kind `identical` says that two
  entries hold the same value, a merge removes entries and renames, and the decision memory is the owner's judgement. The
  broker answers only the owner's login with `admin` on the node (`capability_not_held` to every agent scope). Tags
  (`entry.tag_set`, ADR-167) and aliases (`entry.alias`) have no tool either, and the broker refuses `Origin::Agent` itself;
  since the wiring audit (Q-3) both are on `FORBIDDEN_OPS` as well, with every other human-only op.
- **No applying a tidy-up plan.** `vault.doctor_apply` (ADR-169) is a run of `entry.move`s in one request; like
  `entry.move` it would let an agent carry entries out of its scope. It is on `FORBIDDEN_OPS`, and the broker answers
  only the owner's login.
- **No root-key rotation.** `maintenance.rotate_root` (ADR-076) replaces the key every other key is
  wrapped under and issues a new recovery code; it is on `FORBIDDEN_OPS` — absent, not gated — and
  refuses `Origin::Agent` in the broker as well. Human, `admin`, a fresh second factor and a presence proof.
- **No recovery-code unlock.** `vault.recover` (ADR-163) opens the vault with the printed recovery code and
  re-keys it under a new passphrase and a new code; it is on `FORBIDDEN_OPS` — absent, not gated — and the
  broker refuses an agent token, or a call from inside a registered project folder, before any code is read.
- **No machine-lock change.** `keystore.status`, `keystore.bind` and `keystore.unbind` (ADR-165) are on
  `FORBIDDEN_OPS` — absent, not gated — and the broker refuses an agent token, or a call from inside a
  registered project folder, before anything is read: an agent may neither weaken the lock nor learn
  whether a vault is tied to this Mac.
- **No agent-token issuing, listing, rotation or revocation.** `agent.token_issue`, `agent.token_status`,
  `agent.token_rotate` and `agent.token_revoke` (ADR-164) are on `FORBIDDEN_OPS`, and I-13 forbids `token` in any
  tool name. An agent token is how an agent **authenticates** to the MCP server, never something an agent can make,
  widen, narrow or renew — not even a narrower one, not even its own. The broker refuses all four to `Origin::Agent`
  as well.
- **No 2FA gate change and no directory binding.** `vault.gate_enroll_begin`,
  `vault.gate_enroll_confirm`, `vault.gate_recover` and `node.set_workdirs` are on the forbidden
  list (ADR-064, ADR-066): resetting or replacing the gate, and re-pointing the directories that
  scope every agent launched in them, are policy changes. `vault.gate_recover` needs no login, so,
  like `vault.recover`, the broker also refuses an agent token or a call from inside a registered
  project folder before either factor is read (wiring audit Q-2).

### 3.3 What a denial teaches — **`built`**

A denial that looks like "no results" teaches an agent to retry, rephrase, and eventually find a
way through. Every denial from this surface is explicit and carries a remedy naming the human
action that would resolve it:

```json
{ "error": "node_access_denied", "subject": "northwind", "target": "acme",
  "capability": "reveal", "rule": "R8",
  "message": "Node 'acme' is not readable from node 'northwind'.",
  "remedy": "A human can create a grant: credmgr grant northwind --to acme --scope read --reason \"…\"" }
```

The `remedy` field tells the agent the correct next action is *ask the human*, not *try harder*.
An agent that reports "I need a grant for X because Y" is the behaviour this whole design exists
to produce.

The model is also stated **before** the first denial, in the tool descriptions themselves, so an
agent behaves correctly rather than learning by rejection. `credmgr_whoami`'s description carries
it verbatim: *"You are scoped to one node (resolved from your working directory). You can read
that node, its ancestors, Global, and anything explicitly granted. You cannot reach other nodes,
and no argument to any tool changes that — if you need something outside your scope, say so and
ask the operator."*

The `message` field's only enrichment is **`built`**, and it is narrower than a first read of
`06 §5` might suggest: when the denial is R8 and an expired grant would have allowed the request,
the message names the expiry rather than letting a lapsed grant look identical to one that never
existed. No further reasoning-clause enrichment is designed anywhere in this corpus. An earlier
draft of `06_ACCESS_GRAPH.md §5` carried an example message ending "Nodes at depth 1 are isolated
by design." — that section now explicitly states the broker emits no such sentence and that the
document no longer claims it does, and `06`'s own list of planned access-graph work (`06 §10`)
does not include a reasoning-clause enrichment either. This document previously cited that stale
example as a live `planned` target; it was not one.

### 3.4 Registration

V1 registered a **single global** MCP server entry in the agent client's configuration, shared by
every project. V2 keeps exactly that shape — one entry, no per-project config — because cwd-based
scoping makes per-project entries unnecessary (ADR-020):

```json
{ "mcpServers": { "credmgr": {
    "command": "credmgr",
    "args": ["mcp"]
} } }
```

The server inherits the agent session's cwd, the broker maps it to a node, and the same config
yields a different scope in every project. **One config line, N boundaries** — and no migration
burden when a project is added.

**`built`:** the mechanism. `credmgr mcp` is a real subcommand of the installed binary, and its
transport resolves the socket from the same vault path every other client uses, presenting no
token, so the broker scopes it from the process's own cwd and peer credentials.

**`built` (ADR-164):** an agent token. When `CREDMGR_AGENT_TOKEN` is set in the server's environment, `credmgr mcp`
presents it on every request and the broker scopes the server to that token's one node and capabilities instead of
the cwd. The server reads **only** that variable and **only** a well-formed `cma_` value: it never reads
`CREDMGR_TOKEN`, and it refuses to start on a malformed value or an owner login (`cmt_`), without echoing it, so an
owner login exported into an agent's shell (K-6) never reaches the MCP surface. A revoked or expired token makes every
call answer `session_expired`; the server does not fall back to the cwd scope.

```json
{ "mcpServers": { "credmgr": {
    "command": "credmgr", "args": ["mcp"],
    "env": { "CREDMGR_AGENT_TOKEN": "cma_…" }
} } }
```

**`built` (ADR-141, ADR-142, ADR-143):** the writing of that JSON for the user, from the CLI and the app —
not the broker (ADR-146). `Settings → Agents` and `credmgr agent connect` locate the client's config file
(`17 §4.2`'s detection matrix), show the change as a diff, and on a click (`--yes` in the CLI) copy the file to
`<file>.credmgr-backup-<time>`, merge the one key, write through a temporary file and a rename, and read it
back — never touching a key they did not add and never writing Claude Code's `~/.claude.json` (its row shows the
`claude mcp add` command). `credmgr mcp --print-config [<client>]` emits the snippet for any client, generic JSON
for one with no known config path. **Not built, and not a gap:** an audit-log record and a one-click undo button
for a connect; it is a file written by the owner's own process, and the backup beside it is the trail (ADR-142).

Directories are registered with `credmgr node create … --workdir <dir>` or
`credmgr node workdir <id> <dir>…` (ADR-066); until 2026-09-24 nothing could set them. If cwd
matches no registered `workdirs`, scope falls back to `global` with `list` only, and
`credmgr_whoami` will say so plainly along with how to register the folder. The fallback scope
is **`built`** (`scope.rs::resolve_scope`); the explanatory text in the response is **`planned`**
— `whoami` returns `node`, `capabilities`, `reachable` and (ADR-140) `level`, the caller's own node's security
level, and no guidance field.

## 4. The operation surface — 72 built (`corpus_check`), the rest designed

`18_ENDPOINT_INDEX.md` maps V1's surface onto V2's and is the index. This section is the
inventory: what the broker dispatches, what it refuses, and what the finished surface will be.

### 4.1 Built and reachable — 50 operations

| Namespace | Operations |
|---|---|
| `vault.*` (16) | `init_begin` · `init_confirm` · `status` · `unlock` · `lock` · `gate_verify` · `gate_enroll_begin` · `gate_enroll_confirm` · `gate_recover` · `node_lock` · `node_unlock` · `pending_list` · `pending_accept` · `pending_discard` · `approval_decide` · `approval_get` (`ADR-090`) |
| `entry.*` (10) | `list` · `get` (`ADR-078`) · `reveal` · `create` · `create_batch` (`ADR-073`, multi-field since `ADR-078`) · `update` · `rotate` · `remove` · `restore` · `undo` |
| `field.*` (4) | `add` · `update` · `remove` · `reorder` (`ADR-078`) |
| `node.*` (7) | `list` · `create` (optional `workdirs`) · `set_workdirs` · `update` (rename, `ADR-071`) · `policy` (a patch that widens reach refuses, `ADR-071`) · `seal` · `restore` |
| `notes.*` (2) | `read` · `write` (`ADR-072`) |
| `grant.*` (2) | `list` · `revoke` |
| `maintenance.*` (3) | `verify` · `doctor` · `backup` |
| `audit.*` (1) | `tail` |
| `totp.*` (1) | `code` |
| `util.*` (1) | `generate` (`ADR-087`) |
| top-level (3) | `whoami` · `search` · `graph.snapshot` |

Eleven of these have no V1 ancestor at all and exist because V2 needed them — `whoami`,
`search`, `entry.restore`, `graph.snapshot`, the four `vault.gate_*` operations (`gate_recover`,
the last door, since ADR-064), `totp.code`, `vault.approval_decide` and `node.set_workdirs`
(ADR-066). A twelfth op with no V1 ancestor, `totp.seed`, exists too, and a thirteenth,
`maintenance.rotate_root` (ADR-076), but neither is one of these 48 — both are among the five
built-but-refuse-only operations in §4.2, below. `18_ENDPOINT_INDEX.md §1.8` names the twelve;
`maintenance.rotate_root` is its `§1.4` row. (`vault.init_begin`/`init_confirm` have no V1 route
either; that index lists them under `§1.1`. Nor do `node.policy`, `notes.read`/`notes.write` and the four
`field.*` operations, ADR-071/072/078, listed there under `§1.3`/`§1.2`.)

`maintenance.doctor` is reachable, and its `--rebuild-registry` mode needs a presence proof like the
operations in §4.2 (diff first; `apply: true` writes and then locks the vault so the next unlock loads it from
disk); with no presence key enrolled it refuses with `presence_required`. `node.policy` is
reachable the same way: a patch that tightens or is neutral applies, and one that turns
`descendantRead` on or `siblingVisibility` to `shared` applies with a presence proof and otherwise refuses with
`presence_required` and applies nothing (`ADR-071`, `ADR-098`, `06_ACCESS_GRAPH.md §10.1`). `requireTwoFactor` and `privateNames`
are stored by it and **enforced** since 2026-10-24 (`ADR-085`, `ADR-083`); its `notEnforced` list is
empty and the key stays. Its `maintenance.doctor` sibling gains an opt-in `purgeExpiredSeals`
(`ADR-089`); §4.1c has the shapes.

### 4.1a Response fields that clients depend on

Additive fields (ADR-077); nothing here changes an existing key.

| Op | Field | Meaning |
|---|---|---|
| `vault.status` | `{locked: bool, initialized: bool, pendingApprovals: N}` | `initialized` is false only before `vault.init_confirm` (no durable vault and no registry on disk), so a client can offer "create a vault" without guessing. The bridge defaults a missing `initialized` to `true`. `pendingApprovals` (`ADR-090`) is a bare count of the agent requests still waiting for a person (unexpired, undecided); it names no node, entry or requester. The bridge leaves it out of the page's copy when it is 0. |
| `entry.list` | `entries: [{id, name, type, sensitivity, fieldCount, modified, rotatedAt, expiresAt, hasTotp}]` | Beside `ids`/`names`/`generation`; same gate and filter; only fields the plaintext manifest holds; `rotatedAt`/`expiresAt` are `null` when absent; `hasTotp` is true when the entry carries a TOTP seed (ADR-080; never the seed). **Returned to human sessions only** (`HumanUi`, `Cli`, `Native`); an `Origin::Agent` caller — MCP, a tokenless cwd-scoped process, an explicit agent token — never receives the key. |
| `notes.read` | `{node, markdown, modified, generation}` | `generation` is the manifest generation a following `notes.write` must be based on (read before the note, so a racing write can only make it stale). A caller holding `notes` without `list` can therefore write. |
| `totp.code` | a code, or `malformed_request` | A stored value that is not a usable seed is a typed refusal whose message says why — not base32, or fewer than 80 bits — never the value. Seeds may be stored padded, lower case or grouped. The floor is 80 bits (16 base32 characters), a recorded deviation from RFC 4226 §4's 128 (ADR-077). |
| `maintenance.rotate_root` | `{rotated, recoveryCode, nodesRewrapped, vaultGeneration, filesReplaced, artifactsResigned, completionPending, notResigned[], nodesRekeyed[], filesResealed}` | `recoveryCode` is shown once. `completionPending: true` also carries `meta.vaultLocked: true` (ADR-076). Since ADR-174 every live node gets a new keypair and the orphan a new cold key in the same commit: `nodesRekeyed` (sorted ids) and `filesResealed` (a count, the sealed copies included), as `vault.set_passphrase` answers them. |
| `node.seal` | `{node, sealed: true, archiveMovePending?}` | `archiveMovePending: true` means the registry committed the seal and the archive's file moves, which are idempotent, will be finished by the next unlock (ADR-079). |
| `node.restore` | `{node, restored: true, workdirsDropped?}` | `workdirsDropped` names workdirs another node has claimed since the seal; they are not restored (ADR-079). |

### 4.1c The 2026-10-24 additions — wire shapes (ADR-083…089)

Additive on every existing op; the one new op is `util.generate`. Examples are the broker's actual answers
(values are generated; ids shortened).

| Op | Request | Answer |
|---|---|---|
| `util.generate` | `length?` (8–128, default 20), `symbols?` (default true), `pronounceable?` (default false), `hex?` (default false: lower-case `0-9a-f` only, same length bounds, 4 bits of entropy a character; refused with `pronounceable` or `symbols: true`, and `symbols` is reported false); another key is `malformed_request`. Needs `create` or `update`. **Not an MCP tool.** | `{"value":"q7Vn-2xLw9RtZk4PdE8m","length":20,"symbols":true,"pronounceable":false,"hex":false,"entropyBits":124}` — `entropyBits` is `⌊length × log₂ pool⌋` (pronounceable: the exact figure, 64 at 20). The value is in this answer only: not audited, not stored. |
| `entry.create`, `entry.create_batch`, `node.create`, `node.update` | as before | gain `"warnings": ["mixed_script_name"]` when a name mixes Latin with Greek or Cyrillic letters (accepted, never refused). A look-alike of an existing name (`payroll` with a Cyrillic `а`) is the existing `entry_exists` refusal; names are compared by `credmgr_core::names::canonical_name` (ADR-084) and stored as typed. |
| `entry.create`, `entry.create_batch` | on a `privateNames` node | **ADR-110 (issue #35):** to a caller that may not see names (an agent, MCP, a grantee), a name that is already taken is NOT refused with `entry_exists` - that answer would tell a guesser the name exists. The entry is created under a free name made from the typed one (`name (2)`, `name (3)`, …) and the reply is the same shape as for a free name, without the stored or the assigned name. The owner's login, and every node without `privateNames`, keep the plain `entry_exists` refusal. |
| `entry.create`, `entry.create_batch`, `entry.update`, `entry.rotate`, `field.add`, `field.update`, `field.remove`, `field.reorder`; `entry.get` | as before | **ADR-111 (issue #40):** a field that could be a TOTP seed but is not typed as one (a plain lower-case or padded base32 run of 16-128 characters mixing letters with the digits 2-7; or any such run under a 2FA-like label) is named: the reply gains `"possibleSeedFields": ["f_…"]` (field ids) and `"possible_totp_seed"` in `warnings` (a batch item carries its own `possibleSeedFields`; the batch also warns). `entry.get` marks the field row `"possibleSeed": true`. Absent when there is none, so older replies keep their shape. A field its owner typed - to anything - is never flagged; the owner's answer is `field.update` with `patch: {"type": "totp-seed"}` (CLI: `credmgr field set <name> --field-id <id> --type totp-seed`). It is a hint, not a block: an untyped run stays readable to anything that may reveal the entry until it is typed. |
| `maintenance.backup` | `{passphrase, retain?}` | now also `"complete": true`: the archive holds the whole vault (ADR-112); it is refused with `malformed_request` while a root-key rotation is half finished. **ADR-165 second addendum:** while the machine lock is on (the wrap sealed, or this Mac's bind record for the vault) the archive is written to `<state>/backups/<vault id>/`, outside the vault folder, and the answer says `"outsideVaultFolder": true`; a bound vault whose device key is gone, unreadable or different is `machine_lock_refused` with `reason` `backup_needs_device_key` and nothing is written. |
| `graph.snapshot` | — | a `privateNames` node, to a reader that is not the owner's login: `{"id":"acme","nameHidden":true,"name":null,"label":null,"kind":"project","depth":1,"parentId":"global","entryCount":7,"counts":{"entries":7,"totp":null},"gate":{…},"health":null}`; `gate.twofa` is `"none"` on a vault with no second factor, `"enrolled"` while an enrolment is begun and not confirmed, `"required"` once the vault gate is confirmed and the node's `requireTwoFactor` asks for it (ADR-115, issue #37); below three entries `"entryCount":null,"countHidden":true`. The owner's row is unchanged plus `"nameHidden":true`. |
| `entry.list` | — | same node, same reader: `{"node":"acme","ids":[],"names":[],"entries":[],"nameHidden":true,"count":7,"generation":12}` (`"count":null,"countHidden":true` below three). `search` skips the node; `entry.get` answers `name: null` and every field `label: null`; `vault.pending_list` answers `name: null` with `nameHidden: true`; `notes.read` answers `markdown: null` with `nameHidden: true` and the `generation`. |
| `entry.reveal`, `totp.code`, and under `requireTwoFactor: always` also `entry.list`, `entry.get`, `notes.read`, `vault.pending_list` | — | with a confirmed gate and no fresh second factor: `two_factor_required` `{challenge:"totp", scope, expiresIn}` (ADR-085) |
| `vault.gate_verify` | `{code}` from a logged-in owner session | a **step-up**: `{"locked":false,"elevated":true,"expiresIn":300}` — no token (ADR-085) |
| `entry.undo` | `{node, id, generation, mode?}` | the old keys plus `"ok":true` and `"restored":{"action":"field.remove","entry":"e_…","fieldCount":3}` (or `{"action":"entry.remove","entry":…,"name":…}`); a field edit older than seven days is `not_undoable` (ADR-086). `credmgr_undo` is unchanged. |
| `vault.approval_decide` | `{request, approved, passphrase, code?}` — **only while the vault is locked** | `{"request":"rq_…","node":"acme","entry":"e_…","approved":true,"authorisedBy":"factors"}`; wrong passphrase `wrong_passphrase`, no code with a gate `two_factor_required`, a wrong code or any recovery code `gate_verification_failed` (ADR-088). A reveal on a wholly locked vault now answers `approval_pending` (it used to be `vault_locked`). From a login (no `passphrase`), `approved: true` needs a presence proof once a key is enrolled: `presence_required` without one (ADR-173); `approved: false` never does. |
| `vault.approval_get` | `{request?}` — **read-only, works on a locked vault, decrypts nothing** (`ADR-090`) | with `request`: `{"request":"rq_…","node":"acme","entry":"e_…","nodeLabel":"Acme","entryName":"API_KEY","command":"entry.reveal","state":"pending","expiresIn":97,"requestedAt":1800000100}`; without: `{"pending":[…that shape…]}`, oldest first. A `privateNames` node's `nodeLabel` and `entryName` are `null` with `"nameHidden":true` (always, on a locked vault; the owner's login sees them); `cwd` is the owner's only. An unknown, expired or taken id is `not_found`. On an unlocked vault only the owner's login may ask (`capability_not_held` otherwise). Not an MCP tool. |
| `maintenance.doctor` | `{apply?, purgeExpiredSeals?: bool}` | `fixes[]` gains `{"node":"old","type":"purged-expired-seal","sealedAt":…,"archiveRemoved":true}` (or `would-purge-expired-seal` with `apply: false`) (ADR-089) |
| `node.policy` | — | `"notEnforced": []` |

### 4.1d The 2.0.0 broker operations — wire shapes (ADR-130…135, 2026-11-06)

Nine new ops. **None is an MCP tool** (the forbidden list in §3.2 and test I-13 are unchanged); every one that
costs the owner's finger answers `presence_required` / `presence_failed` as ADR-095 defines, and every one that
costs a fresh second factor answers `two_factor_required {challenge:"totp", scope, expiresIn}` — `scope` is
`global` (the vault's gate) or the node's id (its own gate, ADR-135). Owner = a live login session, never an agent.

| Op | Request | Answer |
|---|---|---|
| `node.rekey` | `{node}` — owner, `admin` on `global` and on the node, node unlocked, fresh second factor(s), presence proof. Refuses `orphan`, a sealed or unknown node, a node with locked-write tray entries (`malformed_request`). Runs under the exclusive request barrier. | `{"node":"acme","publicKey":"<64 hex>","entries":12,"note":true,"history":3,"removed":1}`. The second-factor window is spent. |
| `orphan.destroy` | `{confirm: "destroy-sealed-entries", count, entries?: [id…]}` — owner, `admin`, fresh second factor, presence. `count` must equal what would be destroyed, an explicit `entries` list included (`malformed_request` naming the real number otherwise, checked before the presence proof is spent, ADR-148); an unknown id is `not_found`; absent `entries` = all. | `{"destroyed":4,"sealsForgotten":2,"archivesRemoved":2}`. Never undoable. |
| `search.content` | `{term, node?}` — `reveal` capability; `term` 3–200 characters (`malformed_request`); 12 calls / 60 s per caller (`rate_limited` with the wait); `vault_locked` when locked. An agent never matches what it could not reveal without the owner's approval (ADR-148): nothing on a Sealed node, no high or critical entry on a Guarded one. | `{"results":[{"node":"acme","id":"e_…","name":"database"}],"truncated":false}` — exactly those keys; never a value, snippet, label or field id. |
| `node.export` | `{node, passphrase \| recipients: [age1…]}` — owner, `reveal`, fresh second factor(s), presence; exactly one of passphrase (12+ characters) or 1–16 recipients; `orphan` refused. | `{"node":"acme","format":"age-v1","entries":12,"omittedSeeds":1,"archive":"<base64 age ciphertext>"}`. The plaintext never leaves the broker; 2FA seeds are redacted and counted. |
| `audit.report` | `{from, to, node?}` — owner, `admin`; unix seconds, `from < to`, ≤ 366 days. | `{"from","to","node","records","decisions":{allow,deny,other},"byAction":[{action,count,allow,deny}],"byActor":[…],"byNode":[…],"denials":{"total","reasons":[{action,reason,count}],"recent":[{id,timestamp,actor,action,node,reason}]},"presence":{"uses","byOp":[{op,count}],"refused"},"chain":{"months":["2026-11"],"verified":true}}` — top 50 rows per table; no values, no entry names, no free text. |
| `node.gate_enroll_begin` | `{node}` — owner, `admin` on the node; not `global` / `orphan`. A gate already in force needs its own code, fresh. | `{"node","otpauthUri"}` |
| `node.gate_enroll_confirm` | `{node, code}` | `{"node","recoveryCodes":[10]}` once; `gate_not_enrolling` / `gate_verification_failed` as for the vault's. |
| `node.gate_verify` | `{node, code}` — owner session; shares the unlock backoff | `{"node","elevated":true,"expiresIn":300}`; `malformed_request` "has no second factor of its own" when there is none. The window opens that node only. Written through to disk (ADR-148): a spent recovery code and the TOTP replay floor survive a restart. |
| `node.gate_remove` | `{node}` + fresh own code + presence; **or** `{node, passphrase, recoveryCode}` (the last door; shares the backoff) | `{"node","removed":true}` |

A node with a confirmed gate of its own changes `entry.reveal`, `totp.code`, `entry.get`, `search`, `search.content`,
`notes.read`, … exactly where `requireTwoFactor` already asks (ADR-085): the owner is asked too, the answer's `scope` is
the node's id, the vault's code does not satisfy it, and the node's code does not satisfy another node. A gated node asks
its own code before **every** reveal even when its `requireTwoFactor` is `never` (ADR-148: that setting needs only the
admin gate, so it cannot switch off a factor the admin gate never passed). A gated node is
not sealed (`malformed_request`), and an agent's `entry.reveal` on it while the vault is locked is `vault_locked`, never
an approval request.

### 4.1e The doctor's tidy-up scan — wire shape (ADR-161, 2026-11-14)

One new op, read-only, **not an MCP tool** (§3.2). It writes nothing; every change it proposes is applied by the
owner, one `entry.move` at a time, with that op's own second factor and Touch ID (ADR-158), or every move of one
report at once with `vault.doctor_apply` (ADR-169, below).

| Op | Request | Answer |
|---|---|---|
| `vault.doctor_scan` | `{staleDays?, expiringDays?}` — each 1–3650 (`malformed_request` otherwise), defaults 365 and 30. The owner's login and `admin` on `global` (the gate of `audit.report`); no second factor, no presence. One at a time (`rate_limited`, retry 5 s); at most 10,000 entries, 10 s of value reading and 500 findings of each kind (`truncated: true` when cut). | `{"now","staleDays","expiringDays","nodesScanned","entriesScanned","valuesChecked","skipped":[{node,nodeLabel,reason:"locked"\|"second_factor"\|"not_listed",what:"all"\|"values"}],"truncated","counts":{duplicate_value,misfiled,similar_names,weak,mistyped,expired,expiring,stale},"findings":[{"kind","entries":[{node,nodeLabel,entry,ref,name,generation}],…,"proposal":{action,op:"entry.move"\|null,to?,toLabel?,move?:{node,entry,to,generation},keep?,options?}}]}` — per kind: `match` (`exact`/`probable`), `similarity` + `sameNode`, `field` (the field id) + `fieldLabel`, `reasons`/`reason`, `expiresAt` + `source` (`manifest`/`jwt`), `lastChanged` + `basis` (`rotated`/`modified`). Never a value, a hash, a length or a fragment: duplicates are found by HMAC-SHA256 under a key drawn for this scan and dropped when it returns. |
| `vault.doctor_apply` (ADR-169) | `{moves: [{node, entry, to, generation}], reason?}` — 1 to 500 moves, each exactly a scan proposal's `move` (`generation` is the source node's as the scan read it; a node that is a source more than once carries the same generation each time). The owner's login, `admin` on every node named, a fresh second factor for the vault and for each named node that has its own, and **one** presence proof whose signed digest covers the whole request. Every step is checked first, in order and each seeing the earlier ones done (a stale generation `conflict`, the same entry twice, the same node or the orphan `malformed_request`, an entry not in its source or a node that is not there `not_found`, a name the destination already uses or an earlier step brings in `entry_exists`, a locked node `node_locked`), before any factor is asked for; then each move runs through `entry.move`'s crash-safe commit under the exclusive barrier. | `{"complete":true,"applied":[{…entry.move's answer…,"index"}],"notApplied":0}`; when a move after the first fails, `{"complete":false,"applied":[…],"stopped":{index,node,entry,to,code,message},"notApplied"}` (the moves applied stand, each a whole move, moved back with `entry.move`). A failure at the first move is the request's error, and nothing moved. Never a value. Audit: the generic record of the request, and per move the destination's `entry.move` record (`moved from <source>`), the source's (`moved to <destination> by vault.doctor_apply`) and a `grant.revoke` per revoked grant. |

### 4.1f Tags and merges — wire shapes (ADR-167, ADR-168, 2026-11-20)

Nine new ops, **none an MCP tool** (§3.2). No answer, error or audit record carries a value; no audit record carries a
tag, a key or a name.

| Op | Request | Answer |
|---|---|---|
| `entry.tag_set` | `{node, entry, generation, tags: [string]}` — the whole set; `[]` clears. Each tag is trimmed, lower-cased, inner white space to one `-`; then 1–32 letters, digits or `- _ . : /`; at most 16 distinct (`malformed_request` naming the index). The owner's sessions (`Origin::Agent` → `capability_not_held`), `update` on the node (a locked node `node_locked`), a stale generation `conflict`, a missing entry `not_found`. | `{node, entry, generation, tags}` (the stored, normalised set). `entry.get` and `entry.list`'s rows carry `tags` when there are any; `entry.list {node, tag?}` and `entry.search {node, term, tag?}` narrow to the entries carrying `tag` (normalised the same way) and echo `tag`; a node that hides its names drops `tags` from `entry.get` and refuses a filtered list (`node_access_denied`, rule `private_names`). |
| `merge.suggestions` | `{node, includeDismissed?}` | `{node, generation, valuesCompared, truncated, dismissedCount, suggestions: [{key, kind, reasons, identical, keep, entries: [{entry, ref, name}], dismissed?}]}` — `kind` is `identical`, `shared_value` or `similar_names`; `key` is the entry ids sorted and joined with `+`; `keep` the lowest `ref`. At most 2,000 entries read and 200 suggestions. |
| `merge.apply` | `{node, keep, drop: [id], generation}` — 1–19 distinct ids, none `keep`, all in the node. A fresh second factor after the checks; the generation and plan checked again under the node's write lock. | `{node, keep, merged: [{entry, name, undo}], aliasesAdded, tagsAdded, generation}` — `undo` is the audit id `entry.undo {node, id, generation}` takes to bring that entry back (its name returns; the merge's aliases leave the kept entry; the restore answer adds `mergedInto` and `mergeAliasesRemoved`). |
| `merge.auto` | `{node, key, generation}` — an open `identical` suggestion only (`malformed_request` otherwise). A fresh second factor. | `merge.apply`'s answer plus `key`. |
| `merge.auto_all` | `{node, apply?, generation?}` — without `apply: true` a dry run (no factor); with it `generation` is required and a fresh second factor. | `{node, dryRun, valuesCompared, planned: [suggestion], skipped: [{key, reason, entries}], generation}` and, applied, `merged: [{keep, merged, aliasesAdded, tagsAdded, key}]`. `reason` is `grant`, `aliases` or `tags`. |
| `merge.dismiss` | `{node, key}` — 2–20 sorted ids, all in the node (`not_found` otherwise). | `{node, key, dismissed: true, generation}` (`already: true` when it was). |
| `merge.undismiss` | `{node, key}` | `{node, key, restored, generation}` |
| `merge.dismissed_list` | `{node}` | `{node, dismissed: [{key, entries: [{entry, name \| null}], dismissedAt}]}` newest first. |
| `merge.restore_all` | `{node}` | `{node, restored, generation}` |

Every `merge.*` op: the owner's login with `admin` on the node (else `capability_not_held`), not the orphan node
(`malformed_request`), the node unlocked (`node_locked`). The decision memory is sealed to the node's key in
`nodes/<id>/merge.env` and bound by `mergeSha256` in the signed manifest; a mismatching file is `internal`.

### 4.1b The multi-field operations — wire shapes (ADR-078) and the staged approval (ADR-079)

Every shape below is what `crates/brokerd/src/ops.rs` reads and answers. A field is `{label, value,
type?, masked?}` on the way in (`FieldInput`; an update's `fields` items may also carry an `id`,
`FieldReplace`) and `{id, label, value, type, masked}` when revealed. `type` is one of `password`,
`api-key`, `private-key`, `seed-phrase`, `totp-seed`, `username`, `host`, `port`, `url`, `certificate`,
`text`. An unknown key inside a `fields` item is `malformed_request`. `entryType` is one of `server`,
`database`, `api`, `wallet`, `login`, `ssh`, `certificate`, `token`, `totp`, `env-bundle`, `note`, `other`
(`note-only` is accepted on input); `sensitivity` is `low`, `medium`, `high` or `critical`. For `entryType`,
`sensitivity` and a field's `type` / `masked`, absent means "keep" (on create: infer) and the string
`"auto"` clears a pin; `null` is `malformed_request`. A refusal's message names an index or a field id and
never a label or a value.

| Op | Request (beyond `node`, and `entry` where it names one) | Answer |
|---|---|---|
| `entry.create` | `name`, exactly one of `value` (with `label`, default `"value"`) or `fields[]`; `entryType?`, `sensitivity?` | `{node, entry, pending, fieldCount, fieldIds, generation?}` (`generation` absent when the entry went to the tray) |
| `entry.create_batch` | `entries[]` of the same item body (1–500) | the existing body, and each `created[]` item gains `fieldCount`; every item is validated first; per document ≤ 16 MiB, whole call ≤ 64 MiB |
| `entry.update` | `generation`; at least one of `value` (+ `field`, + `label` to rename), `fields[]` (replaces the list; an `id` keeps a field's identity; unmentioned fields are dropped), `entryType`, `sensitivity`. `fields` excludes `value`/`label`/`field` | `{node, entry, generation, fieldCount, fieldIds}`; keeps no history |
| `entry.rotate` | the same body | the same, plus `rotatedAt`; keeps the previous envelope |
| `entry.get` | — | `{node, entry, name, ref, type, sensitivity, fieldCount, hasTotp, modified, rotatedAt, expiresAt, generation, typeOverridden, sensitivityOverridden, fields: [{id, label, type, masked, typeOverridden, maskedOverridden}]}` — **no value** |
| `entry.reveal` | `fieldIds?` (non-empty; every id must exist) | `{node, entry, fields: [{id, label, value, type, masked}], value?}` — `value` only when exactly one field is returned |
| `field.add` | `generation`, `fields[]` (≥ 1), `position?` (0…count) | `{node, entry, generation, fieldCount, fieldIds, added[]}` |
| `field.update` | `generation`, `field`, `patch{label?, value?, type?, masked?}` (≥ 1 key; unknown keys refused) | `{node, entry, generation, fieldCount, fieldIds}` |
| `field.remove` | `generation`, `field` | the same; removing the last field is `malformed_request` |
| `field.reorder` | `generation`, `order[]` (an exact permutation of the current ids) | the same |
| `totp.code` / `totp.seed` | `field?` — explicit, else the only field, else the one effective `totp-seed` field, else `malformed_request` ("entry has N fields and M TOTP seeds; pass params.field") | unchanged; `totp.seed` still answers `presence_required` |

A `value` edit on a multi-field entry without `field` is `malformed_request` ("entry has N fields; pass
params.field"). **Capabilities and gates:** `entry.get` needs `read`; `field.*` need `update`; all resolve
against the node exactly as `entry.update` does (R1 → `vault_locked` for the whole vault or `node_locked`
for one node), so a read-only agent gets `capability_not_held` for every `field.*` and a cwd-scoped agent
is refused another node's entries with the same `node_access_denied` shape (I-27). `entry.get` has no
approval path (labels are not worth a prompt); a held (tray) entry is `not_found` for it. The four `field.*`
ops and `entry.rotate` keep history and are undone with `entry.undo`; `entry.undo`'s `not_undoable` text now
names them. An allowed call that names a field records its id in the audit detail (`field: f_…`,
`fields: f_…,f_…`) and never a label or a value.

**The staged approval (ADR-079, 4a).** `vault.approval_decide {request, approved}` is still the owner
session's alone (`admin`). Approving decrypts the entry's document then and stages it; the agent's identical retry
of `entry.reveal` is handed it once — narrowed by the retry's own `fieldIds` — and the retry derives no
key. Any lock — explicit, idle or sleep — drops every staged value, and an approval whose vault
locked before the retry is `approval_denied` with `reason: "locked"`. Since ADR-088 (4b) a `entry.reveal` on a
**wholly locked** live vault answers `approval_pending` (it answered `vault_locked` between ADR-079 and
ADR-088) because a person can now decide it with the unlock factors; a decision *without* factors on a
locked vault still answers `vault_locked` and releases nothing. Request ids are 128-bit hex. An undecided request
expires and is denied after 120 seconds, as before.

### 4.2 Built, and gated on a presence proof — 5 operations (+ `maintenance.doctor` rebuild, a widening `node.policy`)

These are fully implemented up to their gate. They parse and validate every parameter, resolve the capability
against the access graph, and then require a **presence proof** (ADR-098; `04_CRYPTO_AND_KEYS.md §5.3`): the owner's
login plus a Secure Enclave signature over the digest of a single-use broker challenge, bound to the operation, the
exact params and the login session. With a verified proof they execute; without one — no presence key enrolled, an
agent or fixture token (which can never hold a proof), any platform but macOS — they return `presence_required` and
change nothing. A proof that was sent and fails answers `presence_failed` with a reason.

How a client asks: `presence.challenge {op, params}` → `{nonce, digest, reason}`; sign the digest with the Enclave
key (Touch ID, or the device password where no fingerprint is enrolled); repeat the original request with
`params.presence = {nonce, signature}`. The CLI and the desktop shell do all three steps themselves when they receive
`presence_required`; the page never sees a nonce, a digest or a signature.

| Op | Why presence, not just a capability |
|---|---|
| `grant.create` | Creating a grant widens a boundary. A grant that an unattended process could create is not a boundary. (The op itself needs the owner's presence proof and, since ADR-174, a fresh second factor when one is enrolled; a single-entry grant must expire within 90 days.) |
| `node.reparent` | Re-parenting changes a node's ancestor set and therefore what it can read — a grant by another name (F-8, I-23). With a proof, depth and kind follow; a cycle and `orphan` are refused. |
| `audit.get` | The full, unredacted record of one decision. `audit.tail`'s redacted feed is the unattended-safe version. |
| `totp.seed` | A code is worth thirty seconds; a seed is worth forever. The seed is returned only here, only to the owner's login with a proof; the desktop app shows it after a Touch ID check (and a fresh second factor if the vault has one), re-masks it after the reveal window, never copies it and clears it on lock (ADR-098), and the CLI has no command. |
| `maintenance.rotate_root` (ADR-076) | Replacing the root key retires every wrap of the old one and issues a new recovery code — the most consequential act the vault has. The arm checks human origin, `admin` on `global`, and a fresh vault second factor (`two_factor_required`, scope `global`) **first**, then the presence proof, then runs `BrokerState::rotate_root` (`crates/brokerd/tests/rotate_root.rs`); the Touch ID wrap and the enrolment file are re-sealed to the same Enclave key. Takes `{passphrase}` (factor one, again) and is on the per-uid auth backoff. |
| `maintenance.doctor` with `rebuildRegistry` | Rebuilding the registry rewrites what every node is allowed to read. A dry run shows the diff; `apply: true` with a proof writes, then locks the vault. |
| `node.policy`, when the patch widens reach | `descendantRead` on or `siblingVisibility: shared` is a grant by another name (ADR-071). |

Each arm asks the same `require_presence` check, so adding a new gated operation did not change the others.

### 4.2b Confirm before showing secrets — `session.confirm` (ADR-150), not an MCP tool

A vault setting, off by default, kept on the `global` node's policy as `revealConfirm: {mode: off|window|everyTime,
windowSeconds: 60|300|900|3600, scope: all|high}` and changed with `node.policy` on `global` by the owner's login only
(turning it off or asking less needs a confirmation from the last 60 s). While it asks, `entry.reveal` (and the shell's
copy) and `totp.code` answer the owner's login `confirmation_required` until it confirms; `totp.seed`, `orphan.reveal` and
`node.export` keep their per-request presence proof instead. `graph.snapshot` gives the owner's login the policy as
`revealConfirm`. A lock ends every confirmation; agents are never asked.

| Op | Params → result | Gate |
|---|---|---|
| `session.confirm` | `{passphrase}` or a presence proof for `session.confirm` with params `{}` → `{confirmed, method: passphrase|presence, expiresIn}` | the owner's login. A wrong passphrase is `wrong_passphrase` and counts in the per-uid unlock backoff. CLI `credmgr confirm [--touch-id]` (passphrase from stdin) |

### 4.2c The recovery-code unlock — `vault.recover` (ADR-163), not an MCP tool

`vault.recover {recoveryCode, newPassphrase, code?}` → `{recovered: true, passphraseChanged: true, rotated: true,
recoveryCode, locked, token?, completionPending, nodesRewrapped, nodesRekeyed, filesResealed, vaultGeneration,
filesReplaced, artifactsResigned, notResigned}`. For a **locked** vault whose passphrase is forgotten: the printed root recovery code opens
`root.wrap.recovery`, the vault is verified under the key it yields, and the same crash-safe root rotation as
`vault.set_passphrase` makes a new root key, a passphrase wrap from `newPassphrase` and a wrap under a **new**
recovery code, answered once; the used code and the old passphrase open nothing afterwards. Since ADR-165's fourth
addendum (N5) the same rotation also gives every live node a new keypair and re-seals what it holds (`nodesRekeyed`, the
ids; `filesResealed`, a count), as `vault.set_passphrase` does, so a copy of the folder from before plus the used code
opens nothing written after. `token` is a login,
as `vault.unlock` hands one out (absent, with `locked: true`, when the rotation committed but left its file moves
to the next unlock). No login is needed. Refused: an agent (`capability_not_held`, before any code is read), an
open vault (`malformed_request`), a vault with no recovery wrap (`not_found`; `vault.status` says
`recoveryUnlock: false`), a wrong code (`recovery_code_mismatch`), an enrolled second factor not given
(`two_factor_required`) or wrong (`gate_verification_failed`). The wrong code and the wrong second factor count in
the per-uid unlock back-off shared with `vault.unlock`. A presence proof is never asked for. Every attempt is
audited; one refused while the vault is locked is written at the next unlock. CLI `credmgr recover`; the app's
Lock screen, "Forgot passphrase? Use recovery code".

### 4.2d The machine lock — `keystore.*` (ADR-165), 3 operations, none an MCP tool

The passphrase wrap `keys/root.wrap.pass` can be sealed a second time under a 256-bit device key kept at
`<state>/machine/lock.key` (mode 0600, outside the vault folder): `CMMLOCK1 ‖ key id (8) ‖ nonce (12) ‖
ChaCha20-Poly1305(device key, plain wrap)`. "Bound" is that form of the file. An unbound wrap is opened exactly as
before. A bound one is opened with the device key first and then by the passphrase; a missing, different, unreadable
key or a damaged file is `machine_lock_refused` with its `reason`, never `wrong_passphrase`. **Bind is a root rotation
that re-keys every project** (ADR-165 addendum, review P0-1), so an older plain wrap or a whole copy made before the bind
opens nothing written after it; what such a copy already held it still opens. A bind record outside the vault folder
(`<state>/machine/vaults/`) lets `status` notice a plain file put back (`plainWhileBound`; an unlock then answers
`machine_lock_refused` `plain_wrap_while_bound` when that file no longer opens the vault) and projects still on a
pre-bind key (`preBindNodes`), and a record that names this folder under another vault id than its `vault.id` (`recordDetached`,
ADR-165 M5: `vault.id` edited or removed, or the folder put back to an older copy; also the owner's `vault.status`
`warnings: ["machine_lock_record_detached"]`, audited once, never repaired). Root rotation and `vault.set_passphrase` re-seal; `vault.recover` never needs the key
and seals the new wrap to this Mac's key (made if missing), or answers `machineLockRemoved` when it cannot. A CredMgr
backup carries the wrap **unsealed** inside its own encryption (addendum P0-2), so while bound it is written outside the
vault folder, to `<state>/backups/<vault id>/` (second addendum, N2). The bind record is keyed by the vault's identity,
`<vault>/vault.id` (32 random hex digits, written by the first bind), not by its path (N4). File tier only: it protects a copy of
the vault folder made after the bind (and, ADR-174 O-2, a Time Machine backup of it, when the device key was made already
excluded from Time Machine: `deviceKeyTimeMachineCovered`); not a stolen or unlocked Mac, whole-disk images, Migration
Assistant or CredMgr backups. **ADR-174 (2026-11-20, the owner's decisions O-1..O-5):** a CredMgr backup of a bound vault
restores on another Mac with the passphrase or the recovery code of its day (O-1, unchanged behaviour, now tested); the
device key is excluded from Time Machine on its temporary file before it reaches its path, its provenance recorded in
`<state>/machine/lock.key.provenance.json`, the exclusion re-asserted at every bind and passphrase unlock, and a key with no
such provenance is put aside to `<state>/machine/retired/` and replaced when a plain vault is bound (unless another vault
on this Mac is bound) (O-2); bind refuses a vault folder in iCloud Drive, `~/Library/CloudStorage/*`, under a
`.dropbox` marker or under a File Provider / iCloud extended attribute (O-3, `malformed_request`, nothing changed); the
stable key id stays (O-4, default kept per ADR-174); each bind phase that can change the vault needs Touch ID where a
presence key is enrolled, else a fresh second factor where a gate is (O-5).

| Op | Params → result | Gate |
|---|---|---|
| `keystore.status` | `{}` → `{bound, tier: "file"/"off", secureEnclave: false, opensHere, sealedKeyId, damaged, deviceKeyPresent, deviceKeyId, deviceKeyUnreadable, deviceKeyModeOpen, deviceKeyForeignOwner, recoveryUnlock, markedBound, plainWhileBound, preBindNodes, inFolderArchives, recordDetached, deviceKeyTimeMachineExcluded, deviceKeyTimeMachineCovered, syncedFolder, bindProof: "presence"/"secondFactor"/"none", warning, protects, doesNotProtect}` — public facts, never a key | the owner's login; an agent refused before anything is read. CLI `credmgr keystore status` |
| `keystore.bind` | **two phases** (second addendum, N1), `phase` required. `{phase:"prepare", passphrase, recoveryCode}` → the status plus `phase`, `changed: false`, `already`, `newRecoveryCode` (the code the commit will install; `null` when `already`), `expiresIn` (seconds, 600) and `nodesToRekey`; nothing durable is written, and the prepared material (new root key, its wrap, the new code) lives in broker memory only, tied to the current root key, until it expires, the vault locks, a rotation happens or `cancel`. `{phase:"commit", recoveryCode}` (the new code typed back whole; omitted when `already`) → the status plus `changed`, `deviceKeyCreated`, `deviceKeyReplaced` (ADR-174 O-2: an older key that may be in Time Machine was put aside), `nodesRekeyed`, `rekeyFailed: [{node, reason}]`, `archivesMoved` and `archivesNotMoved: [{file, reason}]` (archives moved out of `<vault>/backups/`, third addendum M1), and, when it changed something, `orphanKeyReplaced`, `rotation` (as `maintenance.rotate_root` answers, without its `recoveryCode`), `completionPending` and `meta.vaultLocked` when the rotation's last step waits; a code that is not the one shown is `recovery_code_mismatch` (not counted: the same login was just shown it) and the prepared bind still waits; none prepared, expired or overtaken is `malformed_request` "the machine lock was not turned on (nothing changed)". `{phase:"cancel"}` → the status plus `changed: false`. A missing or unknown `phase` is `malformed_request`. A prepared bind belongs to the login that prepared it: another login's commit, cancel or prepare while it waits is `malformed_request` (M4) | the vault open, `admin`, the owner's login; prepare's passphrase opens the wrap (`wrong_passphrase`) and its code opens the current recovery wrap (`recovery_code_mismatch`), both counted in the per-uid back-off (only `prepare` is an auth path); a recovery code set up, a device key path outside the vault folder, every project unlocked, nothing in the tray or the sealed entries, and (ADR-174 O-3) a vault folder no sync service shares; otherwise `malformed_request`, nothing changed. **ADR-174 O-5:** `prepare` and a `commit` that would proceed need a presence proof for exactly that request where a presence key is enrolled (`presence_required`), else a fresh second factor where a gate is (`two_factor_required`, the prepared bind kept); with neither, the passphrase and the recovery codes alone; `cancel` never asks. Idempotent once finished. CLI `credmgr keystore bind` (prompts for both, shows the new code, asks for it back; an empty line cancels) |
| `keystore.unbind` | `{passphrase?}` → the status plus `changed`; the device key stays | the vault open, `admin`, the owner's login, a fresh second factor when one is enrolled, a presence proof every time once a presence key is enrolled, and `passphrase` (counted in the back-off) when neither is; otherwise `malformed_request`. Idempotent. CLI `credmgr keystore unbind` (prompts for the passphrase; empty sends none) |

Both writes take the exclusive request barrier and rewrite `root.wrap.pass` with one atomic write that is read back
before it counts; a temporary file a crash leaves is swept under the vault lock, and a write that landed but could
not be made durable says "the passphrase file WAS changed" (`internal`). The app's Settings > Security > Machine lock
row asks first in a dialog that takes the passphrase and the current recovery code, says what a copy made before now
still holds, that a replaced Mac or another Mac sharing the folder needs the recovery code, and what is not covered,
then shows the new recovery code once.

### 4.2a The presence and Touch ID operations — 8 operations (ADR-098), none an MCP tool

| Op | Params → result | Gate |
|---|---|---|
| `presence.status` | `{}` → `{helper, secureEnclave, biometry, passcode, enrolled: [{id, label, createdAt}], touchIdUnlock}` — public facts only, never a key | the owner's login. CLI `credmgr presence status` |
| `presence.challenge` | `{op, params}` → a single-use 32-byte nonce, the digest to sign and a sentence for the Touch ID dialog; 60 seconds. With `possession: true` (only for `op: "presence.enrol"`, ADR-148) → the challenge the key being enrolled signs, issued with nothing enrolled yet | the owner's login; only for the presence-gated ops |
| `presence.enrol` | `{publicKey (base64 P-256 point), label?, possession: {nonce, signature}}` → the enrolment (key id, label, date). `possession` is the new key's own signature over a possession challenge for exactly these params (ADR-148); without it `malformed_request`, a wrong or spent one `presence_failed`. The enrolled list is kept in the signed registry, so deleting or replaying `keys/presence.enroll` changes nothing | the first key: `admin`, a human and a fresh second factor; any later one needs a proof from an existing key too. CLI `credmgr presence enrol` and the app sign the possession challenge themselves |
| `presence.unenrol` | `{id}` | a proof from an enrolled key. CLI `credmgr presence unenrol` |
| `device.enrol` | `{}` → seals the resident root key to the Secure Enclave key into `keys/root.wrap.se` (Touch ID unlock) | the vault open, `admin`, a fresh second factor and, once a presence key exists, a proof. CLI `credmgr touch-id enable` |
| `device.remove` | `{}` → deletes `keys/root.wrap.se` | same gate as `device.enrol`. CLI `credmgr touch-id disable` |
| `orphan.list` | `{}` → the sealed entries: id, name, ref, type, modified — no value | the owner's login. No CLI command |
| `orphan.reveal` | `{entry, fieldIds?}` → the entry's field values | the owner, a fresh second factor **and** a presence proof every time; the second-factor window is dropped afterwards. The desktop app only: no CLI command |

`vault.unlock` also takes `{method: "device"}` (ADR-098): the Secure Enclave opens the wrapped root key (the user
authenticates with Touch ID or the device password) and the rest is the passphrase unlock's own tail — registry HMAC,
rollback counter, second-factor gate. ADR-148: a caller the broker identifies as an agent (an agent token, or no token
from inside a registered project folder) is refused (`capability_not_held`) before any prompt; for anyone else the
dialog reads "Unlock CredMgr for <process> (pid …) <- <parent> …, in <folder>", filled by the server from the
connecting process (a client's own `_peer` param is discarded; the names are a hint, not proof — ADR-148 addendum),
and a `presence_failed` `cancelled` (a dismissed prompt, or one left until the helper's timeout) or `locked_out`
counts against the per-uid unlock backoff. `keys/root.wrap.se` carries an HMAC tag under the root key; a root-key
rotation re-seals only to a wrap whose tag verifies and refuses an untagged (pre-ADR-148) one until Touch ID unlock is
turned off and on again. `vault.status` reports `touchIdUnlock` so the Lock screen can offer it. The
passphrase and recovery wraps stay; Touch ID is an extra door on this Mac only. New CLI beside the above:
`credmgr unlock --touch-id` and `credmgr node reparent`.

### 4.2e Node-scoped agent tokens — 4 operations (ADR-164), none an MCP tool

| Op | Params → result | Gate |
|---|---|---|
| `agent.token_issue` | `{node, label, capabilities: [list\|read\|reveal\|create\|update…], expiresIn?}` → `{id, label, node, capabilities, effectiveCapabilities, createdAt, expiresAt, lastUsedAt, rotatedAt, token, shownOnce: true}`. `token` is `cma_` + 64 hex, in this answer and nowhere else; `id` is `a_` + 16 hex. `capabilities` must be a non-empty subset of what the node's `agentAccess` gives agents (else `malformed_request` naming the capability); `expiresIn` is 60–604800 seconds, 86400 by default, never unlimited; at most 32 live tokens; not the Orphaned node and not Global (`malformed_request`: issue it for the project the agent works on) | the owner's login (`capability_not_held` to any agent), `admin` on the node, a fresh second factor where enrolled, then a Touch ID proof (`presence_required` with a challenge; the Touch ID sentence names the node, the capabilities, the life and the label). No passphrase fallback: with no presence key enrolled it is unreachable. CLI `credmgr agent token issue` |
| `agent.token_status` | `{node?}` → `{tokens: [{id, label, node, capabilities, effectiveCapabilities, createdAt, expiresAt, lastUsedAt, rotatedAt}], max, defaultExpiresIn, maxExpiresIn}` — metadata only; replaces the planned `{hasToken, last4}` | the owner's login. CLI `credmgr agent token ls` |
| `agent.token_rotate` | `{id, expiresIn?}` → as `token_issue`, with a new `token` and expiry; node and capabilities unchanged; the old secret is refused on its next request | as `token_issue`. CLI `credmgr agent token rotate` |
| `agent.token_revoke` | `{id}` → `{revoked: true, id, label, node}`; the next request with the token answers `session_expired` | the owner's login; no proof (it only removes access). CLI `credmgr agent token revoke` |

A request presenting an agent token is `Origin::Agent` scoped to **exactly** its node — no global, no ancestors, no
descendants, no grants — with the token's capabilities intersected at every request with what the node's
`agentAccess` gives agents now, and ADR-140's security levels applied as for any agent. It is audited as
`Agent:a_…`; a refused request with a revoked, rotated, expired or node-gone token as
`Agent:a_…(revoked|rotated|expired|node_gone)`. The audit records of an issue, rotate or revoke carry
`token a_…; node …; caps …; expires …`. Tokens live in the broker's memory only: a broker restart revokes them all, and a
token's life is checked against both the wall clock and a monotonic deadline. **Sealing a node revokes its tokens**, and a
token whose node is not in the registry is dead, so `node.restore` or a reused id never revives one. A token presented
from a folder registered to another node still works on its own node and writes `anomaly.agent_token_workdir_mismatch`,
filed under the token's node and naming neither the other node nor the folder.

**Who asked.** A reveal approval or a switchboard setting request made with an agent token carries `agentToken: {id,
label}` in `approval.list|get` and `settings.request_list|get` for the owner only, and is keyed by the token's public
id, so a rotation keeps the same request. `vault.approval_get` is refused to every identified agent (an agent token, or a
folder registered to a node) whether the vault is locked or not: its list spans every node. The token-less Lock screen
still reads it while locked, without `agentToken` or the folder. A label holds no control, direction-changing or
invisible character (`malformed_request`).

**The desktop app never puts the token in the webview** (ADR-057's rule for the login). Its `agent_token_issue` and
`agent_token_rotate` commands are hand-written: the shell takes `token` and `shownOnce` off the broker's answer, writes the
token to the concealed clipboard (cleared after 30 seconds and at lock), and answers the rest with `copied: true,
clearAfterSeconds`. If the clipboard cannot take it, the shell revokes the token and answers `copied: false, revoked`.
When a lock came between (which also ends the login a revoke needs), the shell keeps the token's public id, never the
token, and revokes it right after the next unlock, answering `revoked: false, revokePending: true`.

### 4.3 Planned operations — 3, by namespace

Designed here and in `18_ENDPOINT_INDEX.md`; dispatched nowhere. Every one **will** conform to
§1.2's envelope, **will** be authorised through `credmgr_core::access::resolve` rather than
re-implementing authorisation, and **will** append an audit record like every other op.

| Namespace | Planned operations | What the namespace will do |
|---|---|---|
| `audit.*` (2) | `report` · `purge` | `report` will add the stale-grant sweep; `purge` will be human-only and 2FA-gated. |
| `node.export` (1) | `node.export` | 2FA, presence, and an explicit output path. Scope defined in `04 §7`. |

The eight `merge.*` operations left this table on 2026-11-20 with `ADR-168` (none is an MCP tool; §3.2). The four `agent.token_*` operations left this table on 2026-11-14 with `ADR-164` (§4.2e). Three operations left this table on 2026-11-14 with `ADR-165`: `keystore.status`, `keystore.bind` and `keystore.unbind`, the machine lock (§4.2d); none is an MCP tool. `entry.move` left this table on 2026-11-14 with `ADR-158`: `{node, entry, to, generation, reason?}` re-seals one entry to the destination node's key in one crash-safe step (the registry write that binds both manifests is the commit; a stage settles forward or back on the next load) and answers `{node, entry, ref, name, from, generation, toGeneration, grantsRevoked, historyDropped, cleanupWarning?}`, never a value. The owner's login only, `Admin` on both nodes, a fresh second factor and a presence proof on every call; grants on the entry are revoked and its rotation history dropped; a name or alias the destination already uses is `entry_exists`. It is not an MCP tool (§3.2's forbidden list). Five operations left this table on 2026-11-09 with `ADR-156` (the post-launch quick wins): `entry.search`, `entry.get_by_ref`, `entry.history`, `entry.expiring` and `vault.set_passphrase`, which changes the passphrase §1.4's last row verifies and answers a new recovery code; the same change added `entry.set_expiry` and `vault.anomalies_ack`. None of the seven is an MCP tool. Five operations left this table on 2026-09-24 and are in §4.1: `notes.read`/`notes.write` (`ADR-072`),
`node.update`/`node.policy` (`ADR-071`), and `entry.create_batch` (`ADR-073`). Five more left it on
2026-10-03 with `ADR-078`: `entry.get` and `field.add`/`update`/`remove`/`reorder`. The batch's items take
`fields: [...]` since then — already parsed, by the client, from the bulk grammar (`08 §3`): the broker never
parses it.

One reconciliation, kept for the record: until 2026-08-23 `18_ENDPOINT_INDEX.md §1.3` grouped
`node.create · node.reparent · node.restore · node.policy` in one row marked `planned` while three
of the four were dispatched. The index was corrected that day, and the fourth, `node.policy`, is
dispatched since 2026-09-24. Both documents agree on what `ops.rs` contains —
`tools/corpus_check.py endpoints` proves that in both directions.

<!-- figure:broker-request-lifecycle -->

A request that reaches `ops::dispatch` — the one operation-specific step — has already passed
five identical checks, always in this order: peer-uid gate, frame parse, scope resolution (with
anomaly recording), activity touch, auth backoff. Three of those five can end the request before
`dispatch` ever runs: a non-owning uid closes the connection before the first frame is read
(no response), malformed JSON gets an immediate `malformed_request` reply without ever reaching
`handle_request`, and a live backoff lockout returns `rate_limited` — the trace above is the path
where none of them do.

This document warrants only the one figure. The obvious second candidate — built versus planned
operation counts per namespace — already exists as a figure brief in `18_ENDPOINT_INDEX.md §9`,
and rendering the same numbers twice from two hand-maintained sources is how the two copies drift.

## 5. The native shell bridge — **`partial`**

The desktop shell's JS-to-Rust bridge is **allowlisted**: anything not registered as a command is
not callable from the webview, and that allowlist is the boundary that keeps a UI bug from
becoming a vault bug. `18_ENDPOINT_INDEX.md §4` indexes the target command list.

**`built`: a command for every one of the 63 broker ops**, each a thin pass-through to one op —
eight hand-written as of 2026-08-18 (`ADR-057`: `vault.status`, `vault.unlock`,
`vault.gate_verify`, `vault.lock`, `whoami`, `graph.snapshot`, `entry.list`, `entry.reveal`) and
forty-six generated from one `bridge_ops!` table (`ADR-062`'s thirty-four on 2026-09-24, five more the
same day for `ADR-071`…`ADR-073`, `maintenance.rotate_root` for `ADR-076`, five for `ADR-078` and `util.generate`
for `ADR-087`) — plus the
shell's own three commands (`entry_copy`, `copy_text`: the concealed clipboard; `fields_preview`: the
local bulk-paste preview, ADR-078 D5), a typed TypeScript client (`apps/desktop/src/lib/bridge.ts`), and a real
Content Security Policy on the window. They do not reshape, summarise or re-interpret what the
broker said, for the same reason the MCP tools do not.

**`built`: the screens.** They are the KEEP design, precompiled and hosted under the strict CSP
(`ADR-075`), and inside the Tauri shell every screen reads and writes the vault through this bridge:
`apps/desktop/src/vault/index.ts` builds the model on `BridgeSource` whenever a shell is present, and the
actions in `src/vault/actions/*` each make one bridge call and then re-read what it touched — there is no
optimistic write and no local-only write path in a release build. What each control sends is tabulated in
`RELEASE_VERIFICATION.md` (control → bridge command → broker op → expected result), with the real-app result
column filled in by the verification pass. The presence-gated operations
(`grant.create`, `audit.get`, `totp.seed` — a TOTP field's "show seed", which the app displays re-masked and never copies — `maintenance.rotate_root`,
`maintenance.doctor` with `rebuildRegistry`, and opening a sealed entry with `orphan.reveal`) are sent for real:
the shell answers the broker's `presence_required` by asking for Touch ID (ADR-098) and repeats the call, and
with no presence key enrolled the broker refuses, the app says so and changes nothing. Settings → Security → Touch ID
enrols and removes the key and turns Touch ID unlock on and off; the Lock screen shows a fingerprint icon beside the passphrase field. With no shell at all
(a plain browser) a **release** build shows only the broker-unreachable screen; the design's in-memory demo
vault exists in development and test builds alone and is asserted absent from the release bundle
(`scripts/dc/verify-build.mjs`). **`planned`:** the rest of the allowlist, which **will** be:

| Command | Will return | Why it is a command rather than a broker op |
|---|---|---|
| ~~`broker_call(op, params)`~~ | — | **Superseded by ADR-062.** This row planned one generic pass-through so the allowlist would not grow one entry per op; ADR-062 instead gives every op its own command generated from one table, so the allowlist names every op explicitly and the drift guards can hold each command's wire keys against its op. |
| ~~`presence_verify(reason)`~~ | — | **Superseded by ADR-098.** This row planned one command returning a `PresenceProof` to the page. What was built is the opposite custody: the shell signs the broker's challenge itself through the `credmgr-presence` helper (`src-tauri/src/presence.rs`; commands `presence_probe`, `presence_key_create`, `presence_challenge`, `presence_enrol`, `presence_status`, `presence_unenrol`) and retries the call, so the page never holds a nonce, digest or signature. §4.2's operations are reachable through it on a Mac with an enrolled key. |
| ~~`keystore_status()`~~ | — | **Built as a broker op (ADR-165).** The machine lock's tier is the broker's to report, so it is the bridged op `keystore.status` (commands `keystore_status`, `keystore_bind`, `keystore_unbind`, generated by `bridge_ops!`), which drives the Security panel's Machine lock row; the tier is reported as it is (a key file on this Mac, never the Secure Enclave). (`presence_status` tells the Touch ID row what this Mac can do.) |
| ~~`clipboard_copy_concealed(text, ttl)`~~ | — | **Built under other names (WP-E).** The concealed clipboard is the shell's own commands `entry_copy(node, entry, field?)` (the shell reveals the one field itself, writes it with the concealed and transient markers and `CurrentHostOnly`, and clears it after 30 s only if the pasteboard is still its own — and on lock, sleep and quit) and `copy_text(text)` (non-secret text), in `src-tauri/src/clipboard.rs` and `generate_handler`. Both answer a receipt that names the fact and the clock, never the content. **Wired:** the Copy button of a field goes through `entry_copy`, and `navigator.clipboard` appears nowhere in `apps/desktop/src` (`tests/unit/architecture.test.ts`). |
| `notify_approval(request)` | the user's decision | Will raise the one-tap approval prompt for F-15 and return the decision to `vault.approval_decide`. |
| `open_external(url)` | `()` | **Allowlisted hosts only.** An unrestricted opener in a vault UI is a phishing primitive. |
| ~~`llm_detect()` / `llm_connect(client)`~~ | — | **Built under other names (ADR-143).** The shell's `agent_detect`, `agent_snippet`, `agent_plan`, `agent_apply` and `agent_prompt` do the config wiring (`17 §4`); none reaches the broker. |
| `theme_get()` / `theme_set(mode)` | theme | Local preference, never a vault write. |
| `app_integrity()` | signature check | Will have the shell verify its own signature (`21_RELEASE_AND_INTEGRITY.md`). |

Explicitly **not** exposed, then or now: filesystem, shell, HTTP, process spawn, arbitrary path
read or write. Tauri's `fs`, `shell` and `http` plugins are not compiled in, which is a stronger
statement than "not used" — the shell's manifest carries `tauri` with no features and exactly one
plugin.

There is no plugin to name: the scaffold's `opener` plugin and its `greet` command were removed when
the design was hosted (`ADR-075`, 2026-10-02), the shell's capability file grants only `core:default`,
and `src-tauri/tests/shell_config.rs` fails if either comes back. Nothing in the app opens an
external URL, so the `open_external` row above and its **host allowlist** are withdrawn rather than
pending: if a future screen needs to open a link, the allowlist is written first, in the same change.

## 6. The scripting client — **`planned`**

**There is no `@credmgr/client` package.** A previous version of this document showed one being
imported, in the present tense; it exists in no manifest, no lockfile and no source file in this
repository. `crates/core` is a Rust crate and is not importable from a script.

The target design is a thin client library that speaks §1's protocol and holds no key:

```js
const vault = await connect();                 // scope resolved from cwd, exactly as MCP is
const v = await vault.get('DEPLOY_TOKEN');     // throws AccessDenied carrying .remedy
```

Three properties **will** hold, and each one is why the library is worth having rather than
telling people to shell out to the CLI. It **will** talk to the broker and never decrypt: there
will be no exported function that opens an envelope. It **will** carry the broker's structured
denial through as a typed error with `.remedy` intact, so a script fails with the same actionable
message a human would see. And it **will** resolve scope from cwd with no configuration, so a
script placed inside a node's work folder is scoped by where it lives rather than by what it
claims.

**`built` and adjacent to this:** `scripts/emergency-decrypt.mjs`, which is deliberately *not*
part of this client. It is standalone, requires the recovery code, talks to no broker, and is
tested against real Rust-produced fixtures (`crates/cli/tests/emergency_decrypt.rs`) so that the
Rust-written and JS-read wrap formats provably agree. It exists for the case where there is no
broker to talk to (`04 §7`).

## 7. Surfaces that will never exist

**No HTTP API.** V1 ran a loopback HTTP daemon protected by a bearer token. V2 has no HTTP
server, no port, and no bound socket a browser tab — or a malicious page — could reach. The UI is
served by the shell and talks to the broker over the local socket (ADR-019, ADR-025, F-12).

**No remote or sync surface.** Out of scope for V2 and probably permanently: it would change the
threat model completely (`05 §9.3`). The organisation product designed in
`22_ORG_VAULT_SYNC_AND_LICENSING.md` is a separate decision with its own threat analysis, and
nothing in this document's surface anticipates it.

**No agent path to a grant, a seed, a policy change, or the audit log's deletion.** §3.2 is not a
default that a future configuration could relax; it is enumerated in code and enforced by a test
that fails when the registry disagrees with it.

## 8. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `02_ARCHITECTURE.md §3` | the peer-credential identification §1.4's first invariant rests on |
| depends on | `06_ACCESS_GRAPH.md §3` | the capability every operation in §4 is resolved against |
| depends on | `07_TWO_FACTOR.md §5` | the verification rules behind `two_factor_required` and `approval_pending` in §1.3 |
| depends on | `11_MIGRATION.md §1` | why §2.4 removes `migrate` rather than reshaping it |
| depends on | `14_DECISIONS.md` | `ADR-019` (no HTTP surface), `ADR-020` (one global MCP registration, cwd-scoped), `ADR-021` (denials carry a remedy), `ADR-023` (`create`/`update` split), `ADR-026` (approval on demand), `ADR-054` (maintenance ops and their forbidden-list entry), `ADR-055` (`entry.undo`), `ADR-056` (session login), `ADR-059` (the status vocabulary this rewrite applies), `ADR-062` (every op bridged), `ADR-063` (the honoured unlock passphrase), `ADR-064` (`vault.gate_recover`, `credmgr gate enroll`/`recover`), `ADR-065` (the login's reach), `ADR-066` (`node.set_workdirs`), `ADR-071` (`node.update`/`node.policy`), `ADR-072` (`notes.*`), `ADR-073` (`entry.create_batch`), `ADR-075` (the app hosted under the strict CSP), `ADR-076` (`maintenance.rotate_root`), `ADR-077` (no bearer in the audit log, `node_locked`, the additive fields, the 80-bit TOTP floor), `ADR-078` (the field model: `entry.get`, `field.*`, the field-addressed params), `ADR-079` (durable seal and restore, the staged approval) |
| feeds | `13_TEST_PLAN.md §4` | the forbidden-tool list I-13 enumerates, and the invariants I-11/I-12/I-18/I-23/I-25 assert |
| feeds | `17_AIRLOCK_AND_LLM.md §4` | the registration shape §3.4 specifies, which the auto-config writes |
| feeds | `18_ENDPOINT_INDEX.md §1` | the V2 operation names every row of that index maps a V1 route onto |

## 9. Source

**Design.** `ADR-019`, `ADR-020`, `ADR-021`, `ADR-023`, `ADR-025`, `ADR-026`, `ADR-041`,
`ADR-043`, `ADR-044`, `ADR-046`, `ADR-054`, `ADR-055`, `ADR-056`, `ADR-059`, `ADR-062`…`ADR-066`,
`ADR-070` (the backoff's 1-hour cap), `ADR-071`…`ADR-073`, `ADR-075`…`ADR-079`, `ADR-098` (presence and Touch ID) in `14_DECISIONS.md`. `06_ACCESS_GRAPH.md` for the rules every op resolves against;
`16_CROSS_PLATFORM.md` for the named-pipe transport and the keystore tiers §1.4's last row waits
on.

**Code.** `crates/brokerd/src/protocol.rs` (the envelope and the 26-variant `OpError`, including `PresenceRequired` and `PresenceFailed`);
`crates/brokerd/src/server.rs` (framing, the peer gate, `record_decision`, `record_anomaly`, the
auth-backoff wiring); `crates/brokerd/src/scope.rs` (cwd and token scope resolution);
`crates/brokerd/src/ops.rs` (63 dispatched ops, counted with `tools.corpus_check.broker_ops()` —
the authority for every `built` marking in §4); `crates/brokerd/src/state/durable.rs` (§1.4's
live unlock);
`crates/mcp/src/tools.rs` (15 registered tools, `FORBIDDEN_OPS`) and `crates/mcp/src/server.rs`
(the three JSON-RPC methods); `crates/core/src/fields.rs` and `crates/brokerd/src/entry_doc.rs` (§4.1b); `crates/core/src/presence.rs`, `crates/keystore/src/secure_enclave.rs` and `native/macos/presence` (§4.2, §4.2a);
`crates/cli/src/main.rs` and `crates/cli/src/fields.rs` (24 top-level match arms — counting every
nested `node`/`grant`/`gate`/`pending`/`notes`/`field` arm as well gives 47, §2.1);
`apps/desktop/src-tauri/src/commands.rs` (a bridge command per broker op — 8 hand-written, the rest from the
`bridge_ops!` table — with the shell's own `entry_copy`, `copy_text`, `fields_preview` and, since ADR-098, the Touch ID prompt commands in `src/presence.rs` registered beside them in `src/lib.rs`; the per-op command counts in this document were last re-derived at 53 and have not been re-measured for ADR-098);
`scripts/emergency-decrypt.mjs` (envelope versions 1 and 2).

**Tests.** `crates/brokerd/tests/isolation.rs` — I-11 (cwd scoping), I-12 (token/workdir
anomaly), I-18 (create-while-locked), I-22 (`whoami` names only reachable nodes), I-23 (reparent
refused on every current surface), I-25 (concurrent writers). `crates/mcp/tests/i13_tool_registry.rs`
— I-13, the forbidden-list guarantee, walked over the live registry.
`crates/cli/tests/mcp_integration.rs` — the real `credmgr mcp` subprocess against a real broker;
note in §3.1a which tools it does **not** cover (`crates/cli/tests/fields_cli.rs` adds the field tools). `crates/cli/tests/no_secret_in_argv.rs` —
§2.2's structural argv assertion. `crates/cli/tests/emergency_decrypt.rs` — §6's standalone
recovery path. `crates/brokerd/tests/durable_vault.rs` — §1.4's live unlock, `vault.gate_recover`
and `node.set_workdirs`, and — ADR-071…073 — `node.update`, `node.policy`, `notes.*` and
`entry.create_batch`; `rotate_root.rs`, `adr077_ops.rs` and `audit_actor.rs` — ADR-076, ADR-077;
`field_model.rs`, `field_seal_joint.rs`, `seal_durable.rs`, `approval_locked.rs` and `isolation.rs` I-27…I-29 — ADR-078, ADR-079.
`cargo test --workspace -- --list`: 813 tests in 50 test binaries (45 compiled test executables plus
five doc-test targets that find no doc test), counted 2026-10-03 on this tree. The last full pass/fail
run recorded is 571 passing, 0 failing, 41 test binaries (2026-10-02; earlier: 448
passing, 37 binaries on 2026-09-24; 406 passing, 35 test binaries on 2026-09-13 — run
`34743281942`; 397 passing, 33 test binaries, verified 2026-08-18); the run on this tree is the
orchestrator's gate, recorded in `BUILD_LOG.md`. The desktop shell's own suite, outside the workspace
(`cargo test` in `apps/desktop/src-tauri`): 186 tests listed in 12 test executables.

**Verification.** `python3 -m tools.corpus_check endpoints` proves, in both directions, that every
op named in `18_ENDPOINT_INDEX.md` exists in `ops.rs` and every op `ops.rs` dispatches is named
there; `crossrefs` proves every `NN_NAME.md §S` reference in §8 resolves. The two defects in
§3.1a were outside both checks' reach; since 2026-09-24
`crates/mcp/tests/schemas_match_the_broker.rs` compares every MCP tool's declared schema with the
parameters its op reads.

**Figure.** `10_API_AND_MCP_spec.json`, beside this document — the single source of truth for the
figure per `ADR-060` (no separate golden-job file; that convention is `echarts`-kind-only). `kind:
"sequence"`, id `broker-request-lifecycle`, rendered by `tools/docgen/sequence_diagram.py`. Content
re-derived directly from `crates/brokerd/src/server.rs` (`serve_connection`'s peer-uid gate and
read/parse loop, `handle_request`'s `resolve_scope` → `touch_activity` → `auth_backoff` →
`ops::dispatch` order, `record_anomaly`, `record_decision`), `crates/brokerd/src/scope.rs`
(`resolve_scope`, which never itself denies — it only ever narrows or widens the fallback scope),
`crates/brokerd/src/auth_backoff.rs` (`remaining_lockout`), and the envelope shapes in §1.2. The
example request/response pair in the trace is §1.2's own `entry.reveal` example, reused rather than
invented so the figure and the prose agree on one concrete case.
