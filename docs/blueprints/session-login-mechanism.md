---
id: BP-V2-001
classification: public
title: The session/login mechanism (ADR-056)
audience: technical
owner: doc-system
status: needs-verification
export_allowed: true
surface: repo
last_reviewed: 2026-10-02
---

# The session/login mechanism (ADR-056)

### CredMgr V2 · blueprint · 2026-08-17 · v1.0

> `vault.unlock`/`vault.gate_verify` mint a real, non-fixture session token on success — the
> gap ADR-047 traced and nothing but a test fixture could previously close. This is the first
> blueprint document built through the ported visual-engine/docgen pipeline (`tools/PROVENANCE.md`);
> its own generation is the pipeline's own proof of working end to end.

> **Superseded in part (2026-10-02).** This blueprint describes the mechanism as ADR-056 built it, on
> 2026-08-17; read it as that snapshot. Two later decisions changed it: **ADR-065** — a login now
> reaches every non-Orphaned node of its owner's vault, so §4's named limitation no longer holds — and
> **ADR-077** — an audit record names a session by a public id (`HumanUi:s_…`), never by the bearer
> token, which the `audit.tail (token: cmt_…)` call in the figure presents but the log must not
> record. `v2/docs/14_DECISIONS.md` has both.

## 1. What changed

Before this session, three things were true at once: `TokenStore::issue` could mint a real
capability token, `vault.unlock`/`vault.gate_verify` could genuinely unlock the vault, and yet
no code path connected the two — only a test fixture could ever construct an `Origin::HumanUi`
token. `audit.tail`'s per-origin redaction (built, tested, and provably dead code) and ADR-051's
R3-universal-Admin question (real, but undecided because nothing could construct the scope it
was about) both traced back to this one gap.

`ADR-056` closes it. A successful full unlock — either `vault.unlock` with no gate enrolled, or
`vault.gate_verify` completing one that is — now mints a token via `state.tokens.issue(GLOBAL_ID,
ALL_CAPABILITIES, Origin::HumanUi, None)`, registers it so `lock()` can revoke it, and returns
its id on the wire. The CLI captures it the same way `ssh-agent -s` does: `credmgr unlock`
prints `export CREDMGR_TOKEN=<id>`, capturable with `eval "$(credmgr unlock <<< "$pw")"`.

## 2. The five-step flow

<!-- figure:login-funnel -->

1. **`vault.unlock` called.** No passphrase is verified over the wire yet in this build — the
   broker's keystore is fixed at process start (ADR-041 names the real per-request keystore
   selection as Phase 5 territory).
2. **Passphrase verified.** `state.unlock(now)` unwraps the root key via `PlatformKeystore`.
   Wrong passphrase: `OpError::WrongPassphrase`, no token, hot set untouched.
3. **Gate challenge issued, if a gate is enrolled.** `07_TWO_FACTOR.md §3`'s five-step sequence
   — the root key is held (`PendingGateUnlock`) but no node key is derived yet.
4. **`vault.gate_verify` succeeds.** Consumes the TOTP/recovery code, derives every node key
   into the hot set. If no gate was ever enrolled, step 1's own success already reached this
   point directly (`Ok(false)` from `state.unlock`).
5. **Session token minted.** `Origin::HumanUi`, scoped to `global`, every `Capability` in the
   ceiling, `bound_workdir: None`. Registered so the *next* `vault.lock` revokes it.

## 2a. Sequence of the wire calls (docgen — the document-diagram authority)

```
CLI                              credmgrd (ops::dispatch)
 │  vault.unlock {}                    │
 ├─────────────────────────────────────▶
 │                                     │  state.unlock(now)
 │                                     │  no gate enrolled?
 │  { locked:false, token:"cmt_…" }    │
 ◀─────────────────────────────────────┤
 │  export CREDMGR_TOKEN=cmt_…         │
 │                                     │
 │  audit.tail  (token: cmt_…)         │
 ├─────────────────────────────────────▶
 │                                     │  Origin::HumanUi → unredacted
 │  { records: [...] }                 │
 ◀─────────────────────────────────────┤
```

*(Rendered as plain text here deliberately — `tools/docgen`'s own sequence-diagram renderer
takes a `SequenceSpec` JSON, not free-hand ASCII; this placeholder documents the intended
content until that spec is authored. See §5, "what this blueprint does not yet claim.")*

## 3. What this closes

- **`audit.tail`'s redaction-by-origin branch** (ADR-049) is reachable end to end through the
  real compiled `credmgr` binary — proven in `crates/cli/tests/broker_integration.rs`'s
  `unlock_through_the_real_binary_prints_a_token_that_reads_unredacted_audit`.
- **ADR-051's R3-universal-Admin question** is answered: `resolve()`'s R3 stays unqualified by
  capability, deliberately, because after this change `Capability::Admin` is reachable in real
  operation only via a token this mechanism mints, always scoped to `global` — R2 always
  resolves first for the one real shape that exists, so R3's admin-unqualified clause is
  provably inert, not merely undecided.

## 4. The named limitation, not hidden

A `global`-scoped session token cannot administer, list, or audit any node but `global` itself.
Every per-node-Admin-gated op (`node.seal`/`restore`/`reparent`, `grant.create`, `node.create`'s
parent check) resolves against a *specific* node — and per `06_ACCESS_GRAPH.md §1`, a
`global`-scoped subject reaches no other node through R2/R3/R4/R5 (opt-in, off by default)/R6/R7.
This is the same "whole vault graph" gap ADR-047 already named and handed forward to whichever
session wires the native Tauri shell to `credmgrd` for real — this blueprint does not solve it,
and does not claim to.

## 5. What this blueprint does not yet claim

This is the pipeline's first real document, not its finished state. Two things are named rather
than silently done: the §2a sequence is plain text, not a rendered `docgen` `SequenceSpec` (that
spec has not been authored for this flow yet — `sequence_diagram.py` exists and is ported, the
*content* is not written); and no `docgen`-rendered figure appears in this document yet (§2's
figure is the `visual-engine`/ECharts side only) — see `tools/ENGINE_ROUTING_POLICY.md` for which
engine owns which figure type going forward.

## 6. Source

Full design: `v2/docs/14_DECISIONS.md` ADR-056. Code: `crates/brokerd/src/ops.rs`
(`mint_session_token`), `crates/brokerd/src/state.rs` (`session_tokens`), `crates/cli/src/main.rs`
(`cmd_unlock`/`cmd_gate`). Tests: `crates/brokerd/tests/session_login.rs` (6),
`crates/cli/tests/broker_integration.rs::unlock_through_the_real_binary_prints_a_token_that_reads_unredacted_audit`
(1). Blueprint job: `tools/visual-engine/renders/golden/SIM-03-login-funnel.{job.json,svg}`.
