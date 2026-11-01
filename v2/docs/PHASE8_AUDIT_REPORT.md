---
id: V2-900
classification: public
title: Phase 8 audit report (record)
audience: technical
owner: credmgr-v2
status: needs-verification
export_allowed: true
surface: repo
last_reviewed: 2026-10-03
---

<!-- artifact-hardened: Approved With Known Risks @ 09721b5 on 2026-11-01 via three-pass-v1. Evidence: GitHub-hosted CI on pull request #41 (FreeXStudio-Platform/credmgr): all 17 checks green at ee08394, including security.yml (cargo audit, cargo deny, semgrep, isolation suite, endpoint matrix 55/55 operations, desktop bridge) and CodeQL for Rust, JavaScript/TypeScript, Python and Actions with no open alert on the PR; build.yml run 41243452910, all 7 jobs green (macOS 15, Ubuntu 22.04, Windows; Rust 1.78.0 and stable); desktop unit tests 706 passed at 930c502; Playwright 672 and 681 passed in the two lanes that were combined at 930c502 (not re-run together); strict public export PASS, 860 files, literal blocklist not loaded; by-hand click-through of the rebuilt app on a throwaway vault (unlock, lock, auto-lock, graph, tree, search, reveal, copy, add entry, settings, integrity, doctor, audit, backup, capture switch, searchable help); final adversarial audit v2/docs/release-verification/AUDIT_2026-10-31.md (the P0 and both P1 fixed); known risks K-1 to K-20 in v2/docs/PHASE8_AUDIT_REPORT.md sections 4 and 7, each with bound, owner and resolution. Known risks that bear on this document: K-14 the idle lock and a real sleep or screen lock were not exercised by hand on this build; K-19 a seed in an unrecognised shape is not protected until its owner types it; K-20 the licence text has not been reviewed by counsel. K-12 (CI had not run) is closed. Not signed or notarised; Windows and Linux built in CI but not run. Not a claim about anything after 09721b5. -->
# Phase 8 — final adversarial audit of the CredMgr V2 backend (Phases 0–7)

`2026-08-16` · Opus, max effort · one session · `v2/PHASE8_AUDIT_PROMPT.md`

**This phase's job was to doubt Phases 0–7, not to extend them.** No feature or broker op was
added. One security fix, five stale-claim corrections, one brittleness fix, two new tests, one
ADR.

---

## 1. What was checked, and how

Every command below was run in this session against the working tree at `3a91f54`. Nothing is
carried over from `BUILD_LOG.md`'s own claims — where this report cites a number, this session
produced it.

| Check | Command | Result |
|---|---|---|
| Full suite (baseline, before any edit) | `cargo test --workspace` → `/tmp/phase8-full-test.log` | **332 passed, 0 failed, 0 ignored**, 30 binaries, exit 0 |
| Failure sweep | `grep -E "^failures:\|panicked\|[1-9][0-9]* failed"` | no matches |
| Full suite (after this session's fix) | `cargo test --workspace` → `/tmp/phase8-verify-test.log` | see §5 |
| Lints | `cargo clippy --workspace --all-targets -- -D warnings` | see §5 |
| Format | `cargo fmt --all -- --check` | see §5 |
| Dependency policy | `cargo deny check` | see §5 |
| Advisories | `cargo audit` | see §5 |
| Secret scan | `node v1/scripts/guard-no-secrets.mjs --all` | ✓ clean, 228 files |
| Personal-data guard | `node v2/scripts/guard-no-personal-data.mjs --all` | ✓ clean, 166 files |
| Stamp resolvability | `git cat-file -t <sha>` per doc | 21/21 resolve |
| Stamp **drift** | body-hash of each doc at its stamp commit vs. now | 20/21 byte-identical; the 21st explained below |
| Op gate coverage | every `ops::dispatch` arm tabulated for `scope.holds` + `resolve_capability` | 2 arms lacked the graph check — **one was a real bug** |
| Isolation coverage | every `I-N` marker cross-referenced to a real `#[test]` | **24/25**; I-10 absent |
| Repo state | `git status`, `git log`, `git remote -v`, `origin/main..main` | clean, 45 commits, pushed, 0 ahead |

**Method note.** The op-gate check was mechanical (an `awk` pass over `ops.rs` tabulating both
gates per match arm) rather than by reading. That is what surfaced F-1: reading the arm's own
comment would have accepted its stated rationale, which was internally coherent and wrong.

---

## 2. Findings — confirmed real

### F-1 · `node.restore` was authorised against the token, not the node ▸ **SECURITY** ▸ fixed

`crates/brokerd/src/ops.rs:2026` (pre-fix). `node.seal` requires `Capability::Admin` **and**
`resolve_capability(scope, target, Admin)`. `node.restore` required only the former.

An Admin token scoped to project `b` is correctly refused when sealing project `a` (R8) — but
was **accepted** when restoring `a`. `b` reads none of `a`'s data, so this is not a
confidentiality leak; it is a cross-node **integrity** hole. It lets one project unilaterally
undo another's security action, returning values deliberately sealed to human-only (*"no agent,
no CLI, no automation, ever"*) into agent reach for whoever can read `a`. Seal is one of the
four promises the rewrite exists to make.

**Proven before fixing, not reasoned about.** A test was written to assert the correct
behaviour and run first:

```
---- i21b_restore_is_refused_to_an_admin_token_from_an_unrelated_node stdout ----
panicked at crates/brokerd/tests/isolation.rs:1218:
called `Result::unwrap_err()` on an `Ok` value: Object {"node": String("a"), "restored": Bool(true)}
test result: FAILED. 0 passed; 1 failed
```

**Fix:** the same `resolve_capability(scope, target_node, Admin)` call `node.seal` makes. It
resolves correctly *because* the node is absent: `is_strict_ancestor` returns `false` for an
unknown node, so R4/R5/R6 cannot fire, and the only rule that can still allow is R2 (the node
restoring itself — I-21's legitimate path). Everything else is R8.

The obvious symmetric fix — resolve against the sealed node's **parent**, as ADR-051 has
`node.create` do — was rejected and the reasoning matters: for a depth-1 node the parent is
Global, and **R3 allows every node every capability against Global**, so a parent-based check
would have re-admitted exactly the caller being excluded. Full accounting: **ADR-053**.

After: `2 passed` — the new test and I-21 itself, so the fix is an authorisation change and not
a regression.

### F-2 · `scripts/RUNNING.md` documented a completion mechanism the loop abandoned ▸ fixed

Three stale claims in the operator-facing runbook, all of the build's own signature bug class:

1. **`PHASE 6 GATE: GREEN` in `BUILD_LOG.md`** given as the completion condition (line 68). The
   loop uses the **file** `v2/.build-complete`; the grep-a-sentinel design is the self-referential
   bug this build's history is named for. The same file's own diagram (lines 29–34) already
   described the file flag correctly — the table contradicted the diagram four lines below it.
   It also cites **Phase 6**, which is external to this chain.
2. **`exit 4` for `migrate-v1 --commit`** (line 72). `autobuild.sh` has no exit 4 (its codes are
   0, 1, 2, 3, 5) and `migrate-v1` exists nowhere in the tree. This is the *same dead exit-4 path*
   already found and fixed in `CONDUCTOR_PROMPT.md` — fixed in one file, never in this one.
3. **"`migrate-v1 --commit` is grepped out of every session log"** (line 86), listed under a
   heading that promises *"the guard rails are checked, not trusted."* No such grep exists.

### F-3 · `autobuild.sh --help` printed the abandoned mechanism to the operator ▸ fixed

`scripts/autobuild.sh:23` — the header comment still read *"the build is complete (BUILD_LOG.md
records PHASE 6 GATE: GREEN)"*, 120 lines above the code comment explaining at length why the
sentinel is deliberately a file and not that string. Not merely a comment: `--help` printed
lines 2–30, so this was the operator-visible answer to "how does it stop?"

**A second defect found while fixing the first, and caused by it:** the help range was the
hardcoded `sed -n '2,30p'`. Correcting line 23 pushed the last item off the end of `--help`.
Rather than tune the comment to fit the number, the range is now derived — `awk` prints the
leading comment block and stops at the first non-comment line. A hardcoded range that silently
truncates whenever the header is edited is the same brittleness class as the rest of this
report. Verified: `--help` now ends on the closing rule.

### F-4 · The dead "push guard" ▸ fixed

`autobuild.sh` contained a conditional that tested for unpushed commits and did nothing in
either branch — enforcement-shaped code enforcing nothing — while `RUNNING.md` listed *"Nothing
is pushed"* under **"The guard rails are checked, not trusted."** It is not checked; it is an
instruction in `SESSION_PROTOCOL.md` §6 that nothing verifies. The dead block is replaced by a
comment saying so, and `RUNNING.md` now states plainly which rails are facts (exactly one — the
live-vault fingerprint, which is real and does halt on exit 3) and which are promises.

### F-5 · The corpus entry point and agent instructions were stale by the whole build ▸ fixed

`docs/00_README_START_HERE.md:80` and `v2/CLAUDE.md` (three places) still read **"Code (V2): ⛔
none. Build starts at Phase 0"** / **"DESIGN FROZEN — BUILD-READY. NOT BUILT"** / **"Design
corpus only. Zero code."** — across 45 commits, 6 crates and 332 tests.

Worse, both carried a **publication block that had already been lifted**: *"DO NOT PUBLISH YET…
committed locally, NOT pushed, NO GitHub remote created"*, blocked on placeholder donation
addresses. Verified false three ways — `grep -rn REPLACE_ME_BEFORE_PUBLISHING v2/` returns
nothing, `DONATE.md` carries real EVM and BTC addresses (landed in `e49b533`, whose message is
literally *"publication blocker resolved"*), and `git remote -v` shows `origin` →
`github.com/Cryptosours/credmgr` with `main` 0 commits ahead.

This was the most load-bearing stale claim in the repo: an agent obeying `CLAUDE.md` would have
refused an action the operator had already taken. Corrected in place, with the superseded text
recorded rather than deleted (rule 6), and the still-binding half of that block — the donation
safety contract and the no-nag rule — explicitly preserved rather than dropped along with it.

### F-6 · `isolation.rs`'s coverage header was wrong about its own suite ▸ fixed

The module doc said *"Only I-10 and I-13 remain deferred… I-13 needs the MCP tool registry,
unbuilt until Phase 4."* Phase 4 shipped; I-13 has existed since, in
`crates/mcp/tests/i13_tool_registry.rs`. The index of the security suite understated the
security suite — the benign direction, but it is exactly how a *real* gap hides: the same
sentence that was wrong about I-13 was right about I-10, and nothing distinguished them.

Rewritten to name where every out-of-file test lives, and to state I-10's absence and its
condition for closure explicitly.

---

## 3. Investigated and cleared

These looked like defects, or were named as suspects by the audit prompt, and are not.

| # | Suspicion | Verdict |
|---|---|---|
| C-1 | `audit.get` also lacks a `resolve_capability` call | **Correct as written.** It checks the capability, then returns `PresenceRequired` unconditionally. There is no positive path to authorise; it fails closed. |
| C-2 | `audit.tail` redaction keys on `origin == Agent` — fails open for any origin a real transport forgets to set | **Fail-closed in practice.** `scope::derive` returns `Origin::Agent` on *both* untokened paths (registered workdir, and the unknown-cwd fallback); a non-Agent origin requires a token, and **no broker op issues tokens** — there is no `token.*` arm in `dispatch`. So the unredacted branch is unreachable on every transport this build has. Tested: `tail_is_redacted_for_agent_origin_and_full_for_a_human_origin`. Re-check this the moment ADR-047's session/login lands — that is precisely what would make the branch reachable. |
| C-3 | R4/R5 resolve the ancestor relation backwards | **Correct.** R4 is `is_strict_ancestor(target, subject)` (read up); R5 is `is_strict_ancestor(subject, target)` gated on the **subject's** `descendant_read` — matching I-8/I-9, where the policy belongs to the reading parent. |
| C-4 | MCP tools accept a `node` argument, which `10 §3.2` forbids as a "`--node` override" | **Not a bypass, and required.** The broker is the enforcement point; success criterion 1 *demands* an agent naming another node get a structured refusal rather than an empty list, which requires the parameter to exist. I-11 asserts the denial under a tool argument. |
| C-5 | I-13 restates the forbidden list, so it could drift from the doc | **Faithful and conservative.** `FORBIDDEN_OPS` covers every item in `10 §3.2` and adds `node.create`. The test walks the live `registry()`, cross-checks by op *and* by name fragment, and carries an explicit anti-vacuity assertion so an empty registry cannot make it pass. One of the better-built tests in the suite. |
| C-6 | Docs 19 and 22 carry no `artifact-hardened` stamp | **They do** — stamps that honestly say *"not yet hardened"* / *"Pass 1 only"*. Correct behaviour. They were, however, missing from the corpus index; added. |
| C-7 | Every doc "drifted" from its stamp commit | **Artefact of the check, not real drift.** `f2d0fd9` is the commit that *wrote* the stamps, so no file can equal its own stamped revision. Comparing bodies with line 1 excluded: **20 of 21 byte-identical**; `14_DECISIONS.md`'s only delta is `+52 / -1` — ADR-052 itself. Phase 7's gate item 2 holds in substance. |
| C-8 | The `11 §5` stale reference and the migration success criterion | **Genuinely fixed**, and fixed *well* — both carry dated correction notes with the superseded text struck through rather than deleted. `grep -rn "migrate-v1"` finds nothing outside the one doc corrected under F-2. |
| C-9 | `BUILD_LOG.md` has no Session 14 | **Not a gap.** Two entries between 13 and 15 are deliberately unnumbered recoveries, each explaining why. `git log` corroborates. |
| C-10 | `git status` vs. `BUILD_LOG.md` — the twice-repeated uncommitted-work trap | **Clean.** Working tree clean at open, 45 commits, `origin/main` synchronised. The trap did not recur. |

---

## 4. Left open, knowingly

> **Re-read for 2.0.0-beta.1, 2026-10-31 (tree at `b94443c`).** K-1 … K-10 were each checked against the code
> and the corpus as they stand today; the result is the dated *Update 2026-10-31* under each one. K-7 and
> K-10 changed (items closed, a remainder stated); the rest stand. **K-11 … K-16 are new.** Every standing
> risk now ends in a *Bound / Owner / Resolution* block, because the stamp contract (description, bound,
> owner, resolution path with a trigger or date) is checked per risk, not per section. The one-page summary
> is the table in §6. Owners are one of: operator, backend session, front-end team, design team. Milestones
> are GitHub's `2.0.0-rc.1` and `2.0.0`; issue numbers are the repository's (`gh issue list`, read 2026-10-31).

### K-1 · I-10 is not implemented — 24 of 25 ▸ **accepted, not blocking**

- **What:** *"Sealed node → orphan: every transport except native-with-presence is denied;
  **names remain listable**; values unreachable via CLI, MCP and the HTTP-less UI path."*
- **Bound:** the **denial** half is fully proven — `isolation.rs::i21_…` and `i21b_…`, and
  `success_criteria.rs`'s criterion 2 against a real `credmgrd` over a real socket, including
  the harder case that an *orphan-scoped* `List` token is refused too (R0 has no exception).
  Nothing about sealed data is unproven-but-assumed. The unproven half is the **positive** path.
- **Why it cannot be closed now:** no transport can set `presence_attested: true`. This is the
  same honest gap ADR-046 names for hardware keystores and ADR-047 for sessions — Phase 5's
  native shell does not exist, and Phase 6 is external to this chain.
- **Why not "close it" with a denial-only test:** that would make I-10 read as satisfied while
  the half needing a transport went unbuilt. A green checkbox over an untested guarantee is
  worse than an open one.
- **Owner:** whoever builds the native shell. **Resolution:** implement I-10 in full in the same
  change that first makes `presence_attested: true` reachable. Recorded in
  `13_TEST_PLAN.md §3` and in `isolation.rs`'s header so it cannot quietly lapse.

> **Update 2026-10-03 (2.0.0-beta.1).** Unchanged: no transport can set `presence_attested: true`, so the
> positive path of I-10 is still unbuilt. What changed is the set of things waiting on it: with the orphan
> cold key built (ADR-079) there is now real sealed data for that path to open, and the desktop app answers
> every presence-gated control with an explanation and changes nothing. Owner and resolution path as above.

> **Update 2026-10-31.** Re-read: nothing in `crates/` sets `presence_attested: true` (`ops.rs` builds the subject
> with `false`; the `isolation.rs` header still says "Still not implemented anywhere: I-10"). Unchanged, 24 of 25.
> **Bound / Owner / Resolution.** *Bound:* the denial half is proven (`i21_…`, `i21b_…`, criterion 2 against a
> real `credmgrd`); every presence-gated operation (`grant.create`, `node.reparent`, `audit.get`, `totp.seed`,
> policy widening, `rotate_root`) refuses in words and changes nothing, so the gap fails closed and exposes no
> sealed data. *Owner:* backend session, with the operator at the Touch ID sensor. *Resolution:* issue #18
> (milestone `2.0.0-rc.1`); I-10 is implemented in the same change that first makes presence reachable, which
> needs Apple Developer ID signing first (K-4, issue #28).

### K-2 · Ancestor-restore is now narrower than before ▸ **accepted, deliberate**

ADR-053's fix means an ancestor holding Admin can no longer restore a sealed descendant
(`is_strict_ancestor` cannot see a node that is gone). **Bound:** the self-restore path — the
only one any test, CLI flow or documented procedure uses — is unaffected, and the narrowing is
in the safe direction, consistent with *"parents do not read their children unless explicitly
enabled."* **Owner:** the next session that actually wants ancestor-restore. **Resolution:** it
needs the temporary-registry-view approach ADR-053 rejects, plus its own explicit decision — not
a quiet relaxation of the check.

> **Update 2026-10-03 (2.0.0-beta.1).** Re-read in `crates/brokerd/src/ops.rs` (`node.restore`): still
> unchanged. The Admin capability is still resolved against the sealed node's own id, so only the
> self-restore rule can allow, and `isolation.rs::i21b_restore_is_refused_to_an_admin_token_from_an_unrelated_node`
> still pins the refusal. What ADR-079 changed is *how* a permitted restore runs (the seal record lives in
> the signed registry and the orphan copy is reopened with the cold key), not *who* may ask. Bound, owner and
> resolution path as above.

> **Update 2026-10-31.** Unchanged (`isolation.rs::i21b_…` still pins the refusal; no ADR since ADR-053 touches
> it). **Bound / Owner / Resolution.** *Bound:* the self-restore path, the only one any test, CLI flow or
> documented procedure uses, works; the narrowing is toward less access, and a sealed node's data stays sealed
> to its cold copy either way. *Owner:* backend session. *Resolution:* no date, by design — the trigger is an
> operator request for ancestor-restore, which then needs an ADR superseding ADR-053 (the temporary-registry-view
> approach it rejected). No GitHub issue exists for it; file one under `2.0.0` if the operator wants it scheduled.

### K-3 · Named non-gate items still unbuilt ▸ **not this phase's scope**

`maintenance.*`, ADR-047 session/login, and `entry.undo` remain unbuilt, exactly as Sessions 13
and 15 recorded. None is a Phase 7 gate item; all are scoped in `BACKEND_FINISH_PROMPT.md`.
Listed here only so this report is not read as claiming the backend is feature-complete — it is
**gate**-complete, which is a different claim. **Owner:** the operator, when scheduling the next
backend session.

> **Addendum, 2026-08-17 (not an edit to the original finding — this report is a historical
> record of what Phase 8 found, true when written).** A Backend-finish session ran the day
> after this report and closed two of the three items: `maintenance.verify|doctor|backup`
> (ADR-054) and `entry.undo` (ADR-055), both real and tested — see `BUILD_LOG.md` Session 17
> (commit `98a03d7`). **Only the session/login mechanism (ADR-047) remains unbuilt.** Found
> during the 2026-08-17 full-sweep pass; current status now lives in `PROJECT_MAP.md`.

> **Update 2026-10-03.** Nothing to carry: K-3 has been closed since 2026-09-13 (the addendum in §6 records
> the session/login mechanism built as ADR-056, the last of its three items), and it does not appear among
> the standing risks. It is kept above as what Phase 8 found.

### K-4 · O-3 signing certificates ▸ **operator, pre-release**

- **What:** an Apple Developer ID and a Windows code-signing certificate are needed to ship *signed*
  binaries (`21_RELEASE_AND_INTEGRITY.md`). Both remain outstanding operator items.
- **Bound:** it does not block source publication and never blocked the build, and it changes nothing
  about how the vault is encrypted or how access is decided. What an unsigned binary lacks is the
  operating system's proof of who built it: macOS Gatekeeper refuses the tarball's binaries and the app
  until the quarantine flag is cleared by hand (`RELEASE.md`). The checksum file, the bills of materials and
  `scripts/release.sh --verify` let a person confirm that what they downloaded is the bytes the publisher
  listed; that is integrity against the published list, not proof of the publisher.
- **Owner:** the operator. **Resolution:** enrol and buy the certificates, then add signing and notarisation
  to the release script (K-5's N4, "signed, notarized release, gated on D5", is the same step) before any binary release that is not
  labelled unsigned. Until then every release note says so.

> **Update 2026-10-03 (2.0.0-beta.1).** Unchanged in substance: nothing signs, notarises, uploads or
> publishes (`CHANGELOG.md` → release tooling). The release is reproducible (the same commit in the same
> checkout is byte-identical) and ships `SHA256SUMS` and CycloneDX bills of materials; a Homebrew formula is
> prepared and **not published**. The desktop app is sealed ad hoc, which Gatekeeper still refuses (K-5 (4)).

> **Update 2026-10-31.** Unchanged: the 2.0.0-beta.1 `.app` in the by-hand check
> (`RELEASE_VERIFICATION.md` §13) is an unsigned release build. **Bound / Owner / Resolution.** *Bound:* as
> above — provenance rests on `SHA256SUMS` and the bills of materials; encryption and access decisions are
> unaffected. *Owner:* operator (holds the Apple account; enrolment and payment cannot be done by an agent).
> *Resolution:* issue #28 (milestone `2.0.0`), batch 6 of `PRODUCTION_PLAN.md`: sign and notarise the `.app`
> and `.dmg`, wire the updater; until then every release note says "unsigned". Windows code signing is moot
> until Windows is supported (K-16).

### K-5 · The first release is Software-tier and unsigned ▸ **accepted, disclosed** · *added 2026-09-24*

- **What:** `2.0.0-alpha.6`, the first packaged release, protects the vault's root key with the
  `Software` keystore only — Argon2id (m = 256 MiB, t = 3, p = 4) over the operator's passphrase
  (`16_CROSS_PLATFORM.md §4.4`, ADR-041). No Secure Enclave, TPM or Windows Hello wrap exists
  (N3, ADR-046). The binaries are **not code-signed and not notarized** (K-4), so macOS
  Gatekeeper will refuse to open them by double-click and their provenance rests only on the
  published `SHA256SUMS` (`RELEASE.md`), not on an operating-system signature. No presence
  factor exists, so every presence-gated path stays refused (K-1).
- **Bound:** the cryptography does not change by tier — envelopes, node keys, the registry HMAC
  and the rollback counter are identical; only *what unwraps the root key* differs. The vault's
  confidentiality against someone holding the vault directory therefore rests on the passphrase's
  strength against Argon2id at those parameters, which is the same bound V1 has always shipped
  with. Nothing about this is hidden: `Capabilities` reports `Tier::Software`,
  `hardware_backed: false`, `user_presence: false`.
- **Owner:** the operator (decision D5 — buy the Apple Developer ID / Windows certificate, or ship
  unsigned). **Resolution path:** N3 (macOS Secure Enclave, one build session plus one
  human-present Touch ID session) and N4 (signed, notarized release, gated on D5). Until then every
  release note carries this paragraph's substance.

> **Update 2026-10-03 (2.0.0-beta.1) — the bound is restated, not widened.** (1) The disclosure is now
> written once, in `04 §2.4`, and repeated in `README.md`, `RELEASE.md`, `SECURITY.md`, `07 §3` and
> `16 §3`. (2) **Two-factor guards the door, not the safe.** The gate is enforced by `credmgrd`, not by the
> encryption, so a copy of the vault directory plus the passphrase or the recovery code decrypts without the
> second factor; earlier wording ("the root key alone opens nothing") overclaimed and is withdrawn (ADR-079,
> F-h). This belongs in this risk's *bound*: confidentiality against someone holding the vault directory
> rests on the passphrase, or the recovery code, alone. (3) While unlocked, `credmgrd` keeps the root key and
> every unlocked node key in process memory and neither locks its pages nor refuses debuggers (R-1, R-3).
> (4) The desktop app, built by `scripts/release-app.sh`, is sealed ad-hoc: internally consistent, not a
> Developer ID signature, so Gatekeeper still refuses it; K-4's resolution covers it. **Owner and resolution
> path unchanged.**

> **Update 2026-10-31.** The release this risk describes is now `2.0.0-beta.1` (the text above says
> `2.0.0-alpha.6`, which is when it was written). Same Software tier, same Argon2id parameters, same bound.
> **Owner / Resolution made explicit.** *Owner:* operator for the signing half (D5, issue #28), backend session
> for the hardware half. *Resolution:* Secure Enclave keystore tier, issue #19 (milestone `2.0.0-rc.1`), which
> needs signing and the presence work (issue #18) first; the signing half is K-4. Until then the disclosure in
> `04 §2.4`, `README.md`, `RELEASE.md` and `SECURITY.md` is the mitigation.

### K-6 · An exported login reaches every project ▸ **accepted, bounded, owner-decided** · *added 2026-09-24*

- **What:** since ADR-065 a real login session reaches every non-Orphaned node of its owner's
  vault. `credmgr unlock` prints it as `export CREDMGR_TOKEN=…` for `eval` (ADR-056); exported into
  a shell where an AI agent also runs, it hands that agent every project rather than only `global`.
- **Bound:** it never reaches Orphaned (R0); a locked vault or node still blocks reveal and update
  (R1); it dies at lock — explicit, idle, sleep or daemon restart — and on its **own** idle clock
  (15 min unused, even while agents keep the vault unlocked; ADR-065's amendment); it cannot
  replace an enrolled gate without the gate's second factor, fresh (ADR-064's amendment); the
  desktop bridge never exposes it to its webview (ADR-057). The CLI prints a warning line beside it.
- **Owner:** the operator. **Resolution path:** a cwd-bound or single-command owner token for the
  CLI, or keeping owner reach to the desktop bridge only — a product decision, not a bug fix.

> **Update 2026-10-03.** Unchanged in kind. The field model adds no new reach: `field.add|update|remove`
> run through the same entry mutation as `entry.update` and need the same `update` capability, `entry.get`
> never returns a value, and `field.reorder` is not offered to MCP agents. An exported login can still read
> every field of every non-Orphaned entry with `entry.reveal`. The desktop bridge still never exposes the
> token to its webview.

> **Update 2026-10-31.** Unchanged (ADR-065's reach and the 15-minute idle clock are still in `state.rs`; the
> README still carries the warning). **Bound / Owner / Resolution.** *Bound:* as above — never Orphaned, dies at
> lock, own idle clock, no webview exposure, a CLI warning line. *Owner:* operator (a product decision).
> *Resolution:* the operator decides, before `2.0.0`, between a cwd-bound or single-command owner token for the
> CLI and keeping owner reach to the desktop bridge only; trigger: that decision, then one backend session to
> build it. No GitHub issue exists yet; until it does, the mitigation is the README line "Keep `CREDMGR_TOKEN`
> out of any shell an AI agent runs in".

### K-7 · Some bookkeeping is still memory-only ▸ **closed in part by ADR-069, ADR-079, ADR-088 and ADR-089; a smaller remainder stands** · *added 2026-09-24, updated 2026-10-31*

*The three bullets that follow are the finding as written on 2026-09-24. The current state is the
**Update 2026-10-03** after them.*

- **What:** ADR-063 made the registry, manifests, node keys and the 2FA gate durable, and ADR-069
  (same day) the locked-write tray — its metadata now sits beside each pending envelope and the
  tray is rebuilt at the first unlock after a restart. Two things are still not durable: the
  sealed-node records `node.restore` reads within its 7-day window, and the `orphan` node itself —
  `credmgr init` does not create one (the orphan cold key is `planned`, `04 §5`), so `node.seal`
  is unavailable in a vault `init` made.
- **Bound:** no secret is lost or exposed by either; a restart forgets in-window seals (the archive
  files stay on disk).
  Related and also named: approval-on-demand (ADR-042) cannot complete on the live daemon — the
  locked reveal it approves needs the root key, which a locked Software-tier vault does not hold.
  It fails closed (the reveal is refused), never open.
- **Owner:** the next backend session. **Resolution path:** build the orphan cold key (`04 §5`),
  create the orphan node at `init`, and persist seal records beside their archive under the
  registry's HMAC; approval-on-demand waits on a design decision or a hardware tier (N3). The tray
  half is closed (ADR-069).

> **Update 2026-10-03 (2.0.0-beta.1) — ADR-079 closes the first three items and the 4a half of the
> fourth.**
>
> - **Closed.** (1) The orphan cold key exists: `keys/cold/orphan.key`, format `CMCK` v1, 98 bytes, wrapped
>   under a key derived from the root key; it is never in the hot set, it is opened once by `node.seal`'s
>   pre-flight to prove the data is recoverable, and no operation unseals it. (2) `credmgr init` creates the
>   orphan node; an older vault gets one at its first seal or `maintenance.doctor`, never as a side effect of
>   unlock. (3) Seal records live in the signed registry (format 2, under the HMAC and the generation
>   counter), and seal and restore are commit protocols: a restart no longer forgets an in-window seal, and a
>   crash in the middle of one no longer leaves a vault that will not unlock (defect F-a). (4) Approval on
>   demand no longer promises what it cannot keep: the value is staged when the decision is made, any lock
>   drops it, and a wholly locked live vault answers `vault_locked`. Eight defects found while reading the
>   code (ADR-079's table, F-a … F-h — not this report's F-1 … F-6) are fixed in the same change.
> - **What still stands, and its bound.** The factor-bearing half (4b) is *not built*: a
>   `vault.approval_decide` authorised by the unlock factors so one value can be released while the vault
>   stays locked, `vault.approval_get` so the human sees the broker's own description of the request, and
>   `credmgr approve|deny`. Until it exists an agent's request on a wholly locked vault is refused and a
>   person must unlock; **nothing in the product calls `vault.approval_decide`**, so an approval is decided by
>   unlocking, or the request is denied after two minutes. Also not built: purging an expired archive, a
>   `keystore` field in `vault.status`, a `sealed` list in `graph.snapshot`, and offline recovery of orphaned
>   entries (`scripts/emergency-decrypt.mjs` reads live nodes only; whether it should read orphaned ones is
>   the operator's call, OF-1). Every one of these fails closed: nothing is exposed, and expired archives stay
>   encrypted on disk and unreadable. The cold key is exactly as strong as the root key (K-5), and
>   two-factor does not participate in it.
> - **Owner:** the next backend session for 4b — it needs its own review, because a tokenless door must be
>   authorised by factors rather than by origin; the operator for OF-1 and for a purge policy.
>   **Resolution path:** ADR-079's deferred paragraph; the hardware tier (N3) re-wraps the cold key under a
>   Secure Enclave key (`kind 0x02`) with a per-use presence requirement.

> **Update 2026-10-31 — most of the remainder above is now built; what still stands is smaller.**
>
> - **Closed since 2026-10-03.** (1) **Approval 4b** is built (**ADR-088**, not ADR-089): `vault.approval_decide`
>   takes the passphrase and, when a gate is confirmed, the code, and decides one request while the vault stays
>   locked; `vault.approval_get` and `pendingApprovals` (ADR-090) let the person see the request first; the
>   Lock screen calls them, and the by-hand check approved a request there with the vault still locked
>   (`RELEASE_VERIFICATION.md` §13). "Nothing in the product calls `vault.approval_decide`" is no longer true.
>   (2) **The purge of expired seals (WP6) is built** (**ADR-089**): `maintenance.doctor` with
>   `purgeExpiredSeals: true`, opt-in, Admin on `global`, destroys the retained originals of seals older than
>   seven days; the entries stay in `orphan`, sealed to the cold key; a plain Doctor run never purges
>   (ADR-092 fixed a window that had been sending the flag on every run). (3) The **seal/restore commit
>   protocol is isolated** from a concurrent `node.create` / `node.set_workdirs` (ADR-089). (4) Two memory
>   hygiene items: a removed node's hot key is wiped in place before removal (`632af51`, `state.rs`
>   `wipe_then_remove`; the first version wiped a moved copy), and decoded field documents are zeroised on drop
>   (`7234f30`, `FieldDoc` `Drop` in `fields.rs`; this is also K-10 (d)).
> - **What still stands, and its bound.** (a) **OF-1:** `scripts/emergency-decrypt.mjs` reads live nodes only,
>   so there is no offline recovery path for orphaned entries; with the daemon running, a restore within seven
>   days works. (b) **An approval was keyed by (node, entry), not by the requesting session** (ADR-089, "Still
>   open"). The final audit reproduced the consequence (a second caller, with no token, was handed the whole
>   entry a person approved for the first caller's one field) and **ADR-094 closed it on 2026-10-31**: an approval is now one slot per
>   (node, entry, requester) and releases only to that requester, and only the fields it asked for. What remains is
>   narrower: two processes with the same scope (the same work folder, no token) are one requester, and the
>   Lock screen's view of a waiting request still names no requester. (c) **The hot-key table is rebuilt at unlock** (`install_hot_keys_from_root`
>   assigns a new map), and a map that grows while being filled can leave key bytes in freed heap; ADR-089
>   names this and it is not fixed. `lock()` wipes the live values in place, so the exposure is residue in
>   freed memory, which matters only to someone who can already read the broker's memory (K-5 (3)). (d) A
>   `keystore` field in `vault.status` and a `sealed` list in `graph.snapshot` were not re-checked this pass
>   (a broker `meta.sealed` list exists, `ops.rs`); both are display items and expose nothing.
> - **Bound / Owner / Resolution (remainder).** *Bound:* (a) loses nothing while the daemon runs and
>   fails closed — it is a missing offline convenience; (b) needs a same-user process with the same scope (the same work folder) asking for the same fields inside a
>   120 s window, and every release is audited; (c) as stated.
>   *Owner:* operator for (a) (OF-1 is a product decision, default "not built"); backend session for (b)
>   and (c). *Resolution:* (a) decided at `2.0.0` planning, with the offline recovery tool built or dropped
>   by that decision; (c) one backend session in milestone `2.0.0-rc.1`, by building the map in place and wiping the old one
>   ((b) is closed by ADR-094 except for the same-scope case above, which has no planned change). No issues exist yet for
>   (a) or (c); file them with those milestones. The hardware tier (issue #19) later re-wraps the cold key.

### K-8 · Software-tier rollback protection is only as strong as a user-writable file ▸ **accepted, disclosed** · *added 2026-09-24*

- **What:** the external generation counter that stops an older, validly signed registry from
  loading as current lives in the state directory, which the same OS user can write. Since the
  review amendment to ADR-063 a *missing* counter is refused, but an attacker who holds the
  passphrase **and** can restore both an older registry and the matching older counter file (a
  backup of both, taken together) can roll the vault back — including to before the 2FA gate was
  enrolled.
- **Bound:** needs the passphrase and same-user write access to both directories and a matched
  old pair; deletion alone no longer works; nothing about it reveals a secret the passphrase does
  not already reveal — it downgrades the gate, it does not bypass the passphrase.
- **Owner:** the operator. **Resolution path:** a hardware monotonic counter (Secure Enclave /
  TPM, N3); until then, keep backups of the vault and state directories from being restorable by
  anything other than you.

> **Update 2026-10-03.** One addition, no change to the bound: the seal records are now inside the signed
> registry (ADR-079), so the generation counter covers them and a rolled-back registry carries its older
> seal records with it. The attack still needs the passphrase and a matched old pair of directories. Owner
> and resolution path unchanged.

> **Update 2026-10-31.** Unchanged. **Bound / Owner / Resolution.** *Bound:* as above. *Owner:* operator
> (backup hygiene) and backend session (the hardware counter). *Resolution:* the hardware monotonic counter
> arrives with the Secure Enclave tier, issue #19 (milestone `2.0.0-rc.1`); until then the operator keeps
> the vault and state directories' backups from being restorable by anyone else.

### K-9 · A truncated audit tail is re-signed by the next request ▸ **accepted, disclosed** · *added 2026-10-02*

- **What:** the audit log's tip sidecar is what catches removal of the *final* lines (`04 §6`). But
  `credmgr_store::audit::append` reads the log as it stands, appends, and signs the tip over the
  result — it never verifies the log against the tip first, for any request. Truncate the current
  month's log, let the broker handle one more request, and the new tip is signed over the shorter log:
  `maintenance.verify` passes again. Found by the review of the root-key rotation (ADR-076), which
  narrowed its own wording to match rather than change `append`; the weakness predates it (Phase 3).
- **Bound:** needs same-user write access to the audit file. Editing or removing any line but the last
  still breaks the chain walk and is not laundered. The window for detection is "before the next
  request", so `credmgr verify` after any period of doubt, before using the vault again, still sees
  it. It reveals and changes no secret: it lets an attacker with file access hide the *last few
  decisions* from the record.
- **Owner:** the next backend session (a store lane). **Resolution path:** an ADR deciding how
  `append` treats a tip that lags the log by exactly one line after a crash between the log write and
  the tip write, and a month whose tip is missing or signed under another key; then verify-before-append
  (or chain each tip to the previous). The test
  `crates/brokerd/tests/rotate_root.rs::a_tampered_current_audit_month_is_reported_with_the_caveat_that_the_next_record_signs_it`
  will flip when it is fixed, and the rotation's `notResigned` caveat goes with it.

> **Update 2026-10-03 (2.0.0-beta.1).** Re-read in `crates/store/src/audit.rs`: `append` still reads the
> month's lines, pushes one and signs the tip without checking the log against the previous tip, and the
> test named above still exists and still asserts the caveat. The field operations of ADR-078 add more
> audited request kinds, not another way to reach this: every one appends through the same function. Bound,
> owner and resolution path as above.

> **Update 2026-10-31.** Re-read: `append` (`store/src/audit.rs`) still reads the month's lines, pushes one
> and signs the tip over the result without checking the log against the previous tip; the test named above
> still exists (`rotate_root.rs`). Unchanged. **Owner / Resolution made concrete.** *Owner:* backend session
> (a store lane). *Resolution:* the ADR and verify-before-append described above, milestone `2.0.0-rc.1`
> (no issue yet; file one). Until then the operator runs `credmgr verify` after any period of doubt and
> before using the vault again.

### K-10 · Hardening items the field model left open ▸ **accepted, disclosed; item (d) closed 2026-10-31** · *added 2026-10-03*

- **What:** five items ADR-078 records under "Open, recorded". (a) The broker reads one request line with no
  size cap (`server.rs`); a batch may be up to 64 MiB, so a process running as the owner can drive the broker's
  memory use. (b) An entry-level `reveal` grant may never be usable: `entry.reveal` resolves a node-level
  `reveal`, while `entry.list` honours an entry-level grant. (c) The broker's `search` matches names only,
  never labels or values. (d) Decoded field documents are plain `String`s and are not scrubbed from memory on
  drop. (e) Rotation history grows with every field edit and is not pruned.
- **Bound:** (a) is a denial-of-service path for a same-user process and discloses nothing. (b) fails
  closed — a grant that does nothing narrows access, it never widens it. (c) is a functional limit: nothing
  is leaked, a value just cannot be found by searching. (d) matters only to someone who can already read the
  broker's memory, who holds the root key anyway (K-5); the marginal exposure is values that outlive an unlock
  in freed memory. (e) costs disk space only, and history is sealed like everything else.
- **Owner:** the next backend session. **Resolution path:** (a) cap the line, and the batch, in `server.rs`
  and answer a typed refusal; (b) decide whether an entry-level `reveal` grant exists, then make `entry.reveal`
  and `entry.list` agree; (c) a decision — searching values would put plaintext in an index the broker does
  not have today; (d) zeroise-on-drop wrappers for decoded documents; (e) a retention rule, decided in an ADR.
  One standing constraint rides along: if sensitivity ever gates two-factor or reveal, lowering it must become
  a human-only act.

> **Update 2026-10-31.** Re-read item by item. **(d) is closed:** `FieldDoc` now zeroises its value and label
> on drop (`7234f30`; `impl Drop for FieldDoc` in `core/src/fields.rs`, a `Clone` runs the same `Drop`, test in
> `core/tests/field_doc.rs`). **(a) still stands:** `server.rs` reads a request with `read_line` and no size
> cap (a batch is capped at 64 MiB of content, `entry_doc::BATCH_MAX_BYTES`, after the line is read). **(b), (c)
> and (e)** stand as written; for (e) no pruning code was found by search, not by exhaustive reading.
> **Bound / Owner / Resolution (a, b, c, e).** *Bound:* as stated above — (a) a same-user denial of service,
> discloses nothing; (b) fails closed; (c) functional only; (e) disk space only. *Owner:* backend session.
> *Resolution:* (a) and (b) one backend session in milestone `2.0.0-rc.1` (cap the line and answer a typed
> refusal; decide the entry-level `reveal` grant, then make `entry.reveal` and `entry.list` agree); (c) content
> search, issue #32 (milestone `2.0.0`), after an ADR on whether the broker may hold a value index; (e) a
> retention rule by ADR in milestone `2.0.0`. No issue exists yet for (a), (b) or (e); file them with those
> milestones.

### K-11 · The second-factor gate is vault-wide: a 300-second window for every caller ▸ **accepted, disclosed** · *added 2026-10-31*

- **What:** a node marked `requireTwoFactor` asks for the second factor on reveal (ADR-085), but there is one
  gate for the whole vault. A code given for one node opens every node that asks for one, for every caller —
  agents, MCP, CLI and the owner's own tools — for up to 300 seconds (ADR-093 item 3). The per-node secret was
  deferred, not dropped.
- **Bound:** the window cannot be extended and ends on any lock or any node-policy change (`node.policy`
  drops every elevation); an owner's own login is never asked; only nodes the owner marked ask at all; it
  changes who must be present, not what is encrypted (K-5: two-factor guards the door, not the safe). The
  Help text and the dialog say "whole vault, every caller, 300 s" (ADR-092), and the by-hand check read that
  wording in the built app (`RELEASE_VERIFICATION.md` §13).
- **Owner:** backend session (the operator decided the deferral, ADR-093). **Resolution:** a per-node gate
  secret and elevation, designed by ADR, in milestone `2.0.0` — issue #16.

### K-12 · GitHub CI has not run on this release ▸ **CLOSED 2026-11-01: the repository moved into the FreexStudio organisation and CI ran (pull request #41); see `RELEASE.md`** · *added 2026-10-31*

- **What:** every GitHub-hosted job on the repository fails in about two seconds with no runner and no steps
  ("recent account payments have failed or your spending limit needs to be increased"; issue #33; runs
  `41105583397`, `41189880029` and `41192041394` for `security`, and the `promotion-readiness` job of the heavy
  check `41176406571`). So `build.yml` and `security.yml` have not been dispatched and no GitHub required
  context has gone green for `2.0.0-beta.1`. The self-hosted `workspace-tests` job of that heavy check passed
  on `709840c`.
- **Bound:** this is missing evidence, not a failing check. The same gates were run locally at `709840c` and
  recorded in `PRODUCTION_PLAN.md` (workspace tests, both browsers' e2e, real-daemon journeys, design audit,
  clippy, fmt, deny, audit, guards), and a person-driven sweep of the built `.app` is in
  `RELEASE_VERIFICATION.md` §13. What has no second witness is the work only the GitHub-hosted lane does:
  the `security.yml` scans and the matrix step, which `OPEN_WORK_REGISTER.md` records as never having run.
  Nothing is published, so no user is exposed while this stands (K-15 and issue #5 gate publication).
- **Owner:** operator (billing). **Resolution:** the operator fixes the billing block (issue #33, milestone
  `2.0.0-beta.1`); then one agent dispatches `build.yml` and `security.yml` once and reads **job**
  conclusions, not run conclusions; the stamp's evidence is updated from that read. This risk comes off the
  stamp when those jobs are green, and the beta is not published before then.

### K-13 · Dependabot alerts: `glib` in the desktop shell's Linux tree, and npm alerts not yet seen closed ▸ **accepted, disclosed** · *added 2026-10-31*

- **What:** (1) Dependabot alert #4 (medium, RUSTSEC) on `glib` 0.20.0 in
  `v2/apps/desktop/src-tauri/Cargo.lock`, pulled in by Tauri's GTK stack (issue #15). (2) Thirteen npm alerts
  (twelve in `tools/visual-engine`, one in `v1` for `body-parser`; issue #14). Commit `b94443c` bumps the
  lockfiles to the patched versions, but GitHub still listed all thirteen as open when read on 2026-10-31,
  right after the push; their closure is **not verified**.
- **Bound:** (1) affects Linux desktop builds only; the macOS shipping binary does not link `glib`, and no
  Linux desktop build is shipped (K-16). (2) Both manifests are tooling and the legacy V1 package, not the
  shipped Rust app; `tools/visual-engine` is in the public-export allowlist, which is why the lockfile bump
  was made before publication.
- **Owner:** backend session, for both. **Resolution:** (1) bump Tauri when upstream ships a patched `glib`,
  or at the Linux keystore work, milestone `2.0.0` — issue #15; (2) read the alert list after Dependabot
  rescans `b94443c` and close issue #14 when all thirteen are closed, before publication (issue #14,
  milestone `2.0.0-beta.1`).

### K-14 · The 5-minute idle lock and a real sleep or screen lock were not exercised by hand ▸ **accepted until the operator runs them** · *added 2026-10-31*

- **What:** nobody has left the built app unlocked for five minutes, or put the Mac to sleep or locked its
  screen, and watched the vault lock (`RELEASE_VERIFICATION.md` §12.1 and §13: "not done", because the harness
  hides the window first). Lock and ⌘L were exercised in the built app and reload the webview; the desktop
  triggers on a real OS event and on the idle timer were not.
- **Bound:** the broker has its own idle auto-lock (15 minutes by default, ADR-030, `state.rs`) that does not
  depend on the window, so a forgotten unlocked vault still locks. What is unproven is the desktop trigger.
  A failure would leave an unlocked vault open longer than the person expects, up to the broker's own
  clock; it does not open the vault to another user or change any access decision.
- **Owner:** operator (it needs a person at the keyboard). **Resolution:** issue #9 (milestone
  `2.0.0-beta.1`): run the two checks and write the results into `RELEASE_VERIFICATION.md` §13; if either
  fails, a backend-session fix and a re-run before publication.

### K-15 · One shared self-hosted runner serves the repository on a shared host ▸ **accepted until publication** · *added 2026-10-31*

- **What:** the repository's heavy check runs on the credmgr runner, an isolated self-hosted runner on a
  shared VPS (registry grant SW-03). A self-hosted runner that serves a public repository's fork pull
  requests would run strangers' code on that host.
- **Bound:** the repository is private today, so no fork can open a pull request; the runner is registered to
  this repository only and is evidence, never a required context. Path A (a fresh public repository built
  from `tools/public-export`) never carries the registration over. Whether every workflow is already gated to
  same-repository pull requests was not re-checked in this pass.
- **Owner:** operator (the host and the runner are shared infrastructure, not this project's).
  **Resolution:** issue #6 (milestone `2.0.0-beta.1`): de-register the runner or restrict it to
  same-repository pull requests **before** any public flip; gated on the publish decision (issue #5).

### K-16 · Windows and Linux are unsupported in this beta ▸ **accepted, disclosed** · *added 2026-10-31*

- **What:** the packaged product is macOS only. The broker's transport is a Unix socket, so Windows has no
  working transport; no Windows or Linux keystore exists (the Software tier is the only one); the CI
  workflow builds and tests the Rust workspace on Linux, but no Linux desktop build or package is shipped
  (`README.md`, "macOS only"; `16_CROSS_PLATFORM.md`).
- **Bound:** it removes a platform, it does not weaken any: on macOS nothing differs. A person on Windows
  or Linux gets no supported build rather than a weaker one. The disclosure is in `README.md` and
  `04 §2.4`.
- **Owner:** backend session (keystores and transport), with the front-end team for a shell per platform.
  **Resolution:** issue #29 (Windows and Linux keystores, named-pipe transport; milestone `2.0.0`); until
  then the release notes say "macOS only".

### K-17 · A private-names node answers `entry_exists` to a guessed name ▸ **accepted, disclosed** · *added 2026-10-31 by the final audit*

- **What:** on a node with `privateNames`, listing and search hide names, but an agent with the default `create` capability
  learns whether a guessed name exists (`entry.create` answers `entry_exists`, case- and look-alike-insensitively); a miss
  creates an entry. Reproduced on the real daemon.
- **Bound:** names only, never values; the agent must already hold `create` on the node; a miss is visible to the owner as a new entry.
- **Owner:** backend session. **Resolution:** issue #35, milestone `2.0.0-rc.1` (one answer for existing and fresh names, or owner-only create on a private-names node).

### K-18 · `credmgr backup` is a partial archive and nothing restores it ▸ **accepted, disclosed** · *added 2026-10-31 by the final audit*

- **What:** the archive holds entries, manifests, registry, root wraps and keys, but not notes, sealed-node archives, undo archives, rotation
  history or the state directory's generation counter, and no shipped command reads it (`maintenance.doctor --rebuild-registry` needs presence).
  ADR-054 says "restorable with only the passphrase"; that is not true of this build.
- **Bound:** it removes a convenience, not protection: the vault itself is untouched, and copying the vault and state directories (stated in
  `RELEASE.md`) is a complete backup.
- **Owner:** backend session. **Resolution:** issue #36, milestone `2.0.0-rc.1` (a complete archive and a restore command, or a plain statement in ADR-054).

### K-20 · The licence text has not been reviewed by counsel ▸ **accepted, disclosed** · *added 2026-11-01*

`LICENSE` (the FreexStudio Source-Available Licence 1.0, `ADR-096`) was drafted in a working session, not by a lawyer, and it states no governing law or venue. **Bound:** it affects only what others may do with the source; it changes no code, the repository is private and has never been published, and no third party holds the software under any other licence. **Owner:** the operator. **Resolution:** counsel reviews `LICENSE`, `TRADEMARKS.md` and the contribution terms, and a governing law is added, before the repository is made public.

### K-19 · A seed in an unrecognised shape is not protected until its owner types it ▸ **accepted, disclosed** · *added 2026-10-31 by the re-verification*

- **What:** a stored seed is withheld from reveals, and used by `totp.code`, only when it is a seed by one class: an `otpauth://` URI, upper-case base32 at the lengths services issue, groups of four in any case, or a field its owner typed `totp-seed`. A plain lower-case run, or a padded one, cannot be told from a word, so it is treated as text: an agent that can reveal the entry reads it, and `totp.code` refuses it until its owner types the field.
- **Bound:** the owner's own seeds only, in a shape services print rarely (plain lower case, or `=`-padded); an agent already needs `reveal` on that entry; an agent cannot retype a seed away from the class; the owner can type the field in the app's field menu today.
- **Owner:** backend session with the front-end team. **Resolution:** issue #40, milestone `2.0.0-rc.1` (warn when a field could be a seed and is not typed as one; offer the type in Add entry).

> **Considered and not listed as risks (2026-10-31).** (1) *The supporter-extras sealed pack.* The pack
> opens only cosmetics (`PRIVACY.md`: the key "opens nothing but cosmetics and is not a credential"), so a
> leaked code costs a cosmetic upgrade, not data. Who holds the code is an owner decision
> (`PRODUCTION_PLAN.md`, "Owner decisions open"), not a risk to a vault. (2) *The design project's
> `audit-probe.js`.* Whether it may ship under MIT is the operator's licence call (issue #10); until the
> answer is yes it is on the public-export denylist and stays out of the bundle, so the default is the safe
> one. Neither touches confidentiality, integrity or availability of a vault.

---

## 5. Final verification — after every change in this session

Re-run from scratch after the ADR-053 fix, the new test, and all six documentation
corrections. Not a cached result, and not the baseline run from §1.

```text
$ cargo test --workspace                      # → /tmp/phase8-verify-test.log
test result: ok.   333 passed; 0 failed; 0 ignored     (30 binaries, exit 0)
  332 inherited + 1 new (i21b_restore_is_refused_to_an_admin_token_from_an_unrelated_node)

$ grep -E "^failures:|panicked|[1-9][0-9]* failed" /tmp/phase8-verify-test.log
(no matches)

$ cargo clippy --workspace --all-targets -- -D warnings
exit 0   ·   0 warning/error lines

$ cargo fmt --all -- --check
exit 0   (no diff)

$ cargo deny check
advisories ok, bans ok, licenses ok, sources ok        exit 0

$ cargo audit
Loaded 1216 security advisories; scanned 101 crate dependencies
exit 0   (no vulnerabilities)

$ semgrep --config auto crates/
Ran 51 rules on 51 files: 0 findings.

$ node ../v1/scripts/guard-no-secrets.mjs --all
guard-no-secrets: ✓ clean (167 files scanned)

$ node scripts/guard-no-personal-data.mjs --all
guard-no-personal-data: ✓ clean (167 files scanned)
```

**Scope note on the fixes.** Six of the seven corrected files are tracked and land in this
session's commit. The seventh, `v2/CLAUDE.md`, is **deliberately gitignored**
(`v2/.gitignore:117`) — it is local agent instruction, never published — so its F-5 corrections
exist on disk for the next session but carry no commit sha. Stated here rather than letting the
commit list imply a coverage it does not have. It also means the *published* repo never carried
the "DO NOT PUBLISH YET" text; the tracked half of F-5 is `docs/00_README_START_HERE.md`.

---

## 6. Status

<!-- artifact-hardened-status: Approved With Known Risks -->

### **Approved With Known Risks**

The backend does what the corpus says it does. Every Phase 7 gate item was re-verified
independently and holds — including gate item 2, which turned out to hold for a subtler reason
than the naive check suggests (C-7). The one real security defect found (F-1) was proven with a
failing test, fixed, recorded in ADR-053, and is covered by a regression test that fails if the
fix is reverted. Six stale claims were corrected, one of which — F-5 — would have made an agent
refuse work the operator had already authorised.

`Approved` outright is not the honest status while **K-1** stands: I-10 is a specified isolation
test with no implementation, and the isolation suite is the stated justification for the entire
rewrite. Its denial half is proven and its positive half is genuinely blocked on a transport
that does not exist — but "24 of 25, and here is exactly which one and why" is a different claim
from "the suite passes", and the corpus should not round one to the other.

Each known risk carries the four things the portfolio's Three-Pass rule requires — description,
bound, owner, resolution path — in §4: **K-1** (I-10 unimplemented), **K-2** (ancestor-restore
narrowed, deliberate), **K-3** (named non-gate items unbuilt — **closed 2026-08-17**, see the
addendum below), **K-4** (signing certificates, operator, pre-release). None blocks shipping the
backend; K-1 and K-2 both resolve in the same change that builds the native transport.

> **Addendum, 2026-09-13 (not an edit to the 2026-08-16 finding — §4's K-3 and the list above
> record what Phase 8 found, true when written).** **K-3 is closed and no longer stands as a
> known risk**, so the standing risks behind the `Approved With Known Risks` status above are
> **K-1, K-2 and K-4** only. All three of K-3's named items were built the day after this audit.
> Two were already recorded in §4's 2026-08-17 addendum: `maintenance.verify|doctor|backup`
> (ADR-054) and `entry.undo` (ADR-055), both tested, `BUILD_LOG.md` Session 17, commit `98a03d7`.
> The third — the ADR-047 session/login mechanism, which that addendum still listed as unbuilt —
> landed the same day as **ADR-056** (`14_DECISIONS.md`, `BUILD_LOG.md` Session 18, commit
> `11e5dd5`): a real `vault.unlock` / `vault.gate_verify` success now mints a real,
> global-scoped, `Origin::HumanUi` token, which closes `audit.tail`'s redaction-reachability gap
> (C-2) and answers ADR-051's R3-universal-Admin question by construction. ADR-056 names one
> deliberate limitation it does **not** close — a `global`-scoped session token cannot administer
> any node but `global` itself, which stays Phase 6 / native-shell territory per ADR-047's own
> hand-off. `PROJECT_MAP.md` records the result as *"No named backend item remains."*
> **K-1, K-2 and K-4 are unaffected and still stand.**

> **Addendum, 2026-09-24 — what "never exercised against a real vault" was hiding.** The
> sentence below turned out to be load-bearing. Run for the first time with the real `credmgrd`
> and `credmgr` binaries against a vault `credmgr init` had just created, the backend could not
> open that vault: `vault.unlock` unwrapped with the daemon's start-up placeholder keystore and
> answered `wrong_passphrase` to the right passphrase; nothing loaded a vault from disk after a
> restart; and every mutation — entry names, nodes, grants, the 2FA gate — lived only in memory,
> so a restart kept the ciphertext and lost what it meant. All 406 tests passed throughout,
> because each builds its own correctly-keyed state. Fixed by **ADR-063** (live unlock,
> load-from-disk, write-through), **ADR-064** (persisted gate, and the last door that closes
> Phase 5 gate line 6), **ADR-065** (a login reaches its owner's whole vault — the gap ADR-056
> named) and **ADR-066** (directories can be bound to a node), each proven end to end with the
> real binaries and in `crates/brokerd/tests/durable_vault.rs`. New known risks **K-5, K-6, K-7**
> above, plus **K-8**, found by the adversarial review that ran over those ADRs the same day (every
defect it found was fixed; K-8 is the bound that remains). Two more code defects surfaced the
same day and were fixed with decisions behind them: the manifest's per-entry `sha256` was a
plaintext digest, an offline oracle for guessable values (**ADR-067**, gap G-12), and a
login that idled out was silently demoted to its holder's cwd scope instead of refused
(**ADR-068**). **The standing risks are now K-1, K-2, K-4, K-5, K-6, K-7 and K-8.**

> **Addendum, 2026-10-02 — the endpoint matrix, and what it closed and found.** The endpoint matrix
> (`scripts/endpoint-matrix.py`) calls every broker op over the real socket against the real
> `credmgrd`; its first runs, and the independent verification of them, found two defects, both in
> code this audit had not exercised end to end; a third finding, a weakness, came from the review of
> the root-key rotation (ADR-076). **Closed:** (1) **the session token
> was written to the plaintext audit log** — since ADR-056 (`2.0.0-alpha.4`) every record made under a
> login carried the bearer as its `actor`, readable through `audit.tail` by any caller holding `list`,
> so a process running as the owner could replay it as the owner: high severity, local, fixed by
> **ADR-077**, with what an existing vault still holds stated in `SECURITY.md` ("Session token in the
> audit log"); (2) **`totp.code` panicked the connection thread on a short stored
> seed** (MX-1) — now a typed refusal below 80 bits, and a panic inside any op is answered as
> `internal`. Also corrected: a locked *node* answered `vault_locked`, which logged the desktop app out
> (now `node_locked`, ADR-077). **Found by the rotation review, and recorded as a new known risk:**
> **K-9** above. **K-7 is unchanged and now pinned by the matrix** — three known-gap rows expected
> to fail and two that pass only while the gap holds, all K-7 (the orphan cold key); the root-key
> rotation (ADR-076) refuses, changing nothing, while `keys/` holds a file it cannot re-wrap
> (`root.wrap.se`, `cold/*`), so building K-7's orphan key means teaching the rotation to re-wrap
> it. K-1 now also covers the
> rotation itself, which the wire refuses with `presence_required` (after the human, `admin` and
> second-factor checks) until presence can be attested. **The standing risks are K-1, K-2, K-4, K-5,
> K-6, K-7, K-8 and K-9.**

> **Addendum, 2026-10-03 — 2.0.0-beta.1.** Three changes since the addendum above. **K-7 is closed in part**
> (ADR-069, ADR-079; the orphan cold key, the orphan node at `init`, durable seal records and an approval that
> never outlives a lock) and what remains of it is bounded in §4. **K-5's bound is restated** and is now
> written once, in `04 §2.4`: the Software tier means the passphrase is the key, and two-factor guards the
> door, not the safe. **K-10 is new** (the open items ADR-078 recorded). K-1, K-2, K-4, K-6, K-8 and K-9
> stand as written, each with the dated update in §4 where the release changed anything about them. **The
> standing risks are K-1, K-2, K-4, K-5, K-6, K-7 (remainder), K-8, K-9 and K-10**; each carries a
> description, a bound, an owner and a resolution path in §4, which is what keeps this status at `Approved
> With Known Risks` rather than a downgrade.

> **Addendum, 2026-10-31 — the known-risks table for 2.0.0-beta.1 (tree at `b94443c`).** Every K-n in §4 was
> re-read against the code and the corpus. **Closed or narrowed since 2026-10-03:** K-7's approval 4b
> (ADR-088, with ADR-090's `vault.approval_get`), its purge of expired seals (ADR-089), its seal/restore
> isolation (ADR-089), the hot-key wipe (`632af51`) and K-10 (d), decoded field documents zeroised on drop
> (`7234f30`). **New:** K-11 … K-16. **Not listed, with reasons:** the supporter-extras pack and `audit-probe.js`
> (§4, after K-16). **The standing risks are K-1, K-2, K-4, K-5, K-6, K-7 (remainder), K-8, K-9, K-10 (a, b, c,
> e) and K-11 … K-19**; K-3 is closed. The table is the place the stamp cites; each row's long form, with
> evidence, is the K-n section in §4. A row with no issue number has none yet: *Resolution* names the
> milestone and the trigger, and the issue is to be filed.

| ID | Risk (one line) | Bound (what it does not affect) | Owner | Resolution (trigger / milestone / issue) | Status |
|---|---|---|---|---|---|
| K-1 | I-10 positive path unimplemented: 24 of 25 isolation tests | Denial half proven; presence-gated ops refuse in words, nothing sealed is exposed | backend session (+ operator at the sensor) | Same change that makes presence reachable; #18, `2.0.0-rc.1`; needs signing (#28) | Standing |
| K-2 | Ancestor-restore narrower than before (ADR-053) | Self-restore unaffected; narrowing is toward less access | backend session | Trigger: operator asks for it, then an ADR superseding ADR-053; no date, no issue | Standing |
| K-3 | Named non-gate items unbuilt | — | — | Built 2026-08-17 to 2026-09-13 (ADR-054, 055, 056) | **Closed** |
| K-4 | Binaries unsigned, not notarised | Encryption and access unchanged; integrity vs the published `SHA256SUMS` still checkable | operator | #28, `2.0.0`; release notes say "unsigned" until then | Standing |
| K-5 | Software tier: the passphrase is the key; two-factor guards the door, not the safe | Same cryptography on every tier; confidentiality rests on passphrase strength vs Argon2id (256 MiB, t=3, p=4) | operator (signing), backend session (hardware) | Secure Enclave tier #19, `2.0.0-rc.1`, after presence (#18) and signing (#28) | Standing |
| K-6 | An exported login reaches every non-Orphaned project | Never Orphaned; dies at lock and on its own 15 min idle clock; not exposed to the webview | operator | Operator decides before `2.0.0` (cwd-bound token vs bridge-only); no issue yet; README warning meanwhile | Standing |
| K-7 | Remainder: no offline recovery of orphaned entries (OF-1); (b) closed by ADR-094 except for processes sharing one scope; hot-key map rebuilt at unlock | Fails closed; residue only matters to someone who can already read broker memory; daemon restore works within 7 days | operator (OF-1), backend session (rest) | OF-1 decided at `2.0.0` planning; the rest `2.0.0-rc.1`; no issues yet | Closed in part |
| K-8 | Rollback protection is a user-writable counter file | Needs passphrase + same-user write access to a matched old pair; downgrades the gate, reveals nothing | operator (backups), backend session (hardware counter) | Hardware counter with #19, `2.0.0-rc.1` | Standing |
| K-9 | A truncated audit tail is re-signed by the next request | Needs same-user file write; hides the last few decisions only; reveals no secret | backend session | ADR + verify-before-append, `2.0.0-rc.1`; no issue yet; `credmgr verify` meanwhile | Standing |
| K-10 | Hardening leftovers: (a) request-line size, (b) entry-level reveal grant, (c) search names only, (e) rotation history grows. (d) closed | (a) same-user DoS, discloses nothing; (b) fails closed; (c) functional; (e) disk only | backend session | (a), (b) `2.0.0-rc.1`; (c) #32, `2.0.0`; (e) `2.0.0`; no issues yet for (a), (b), (e) | Closed in part |
| K-11 | Second-factor gate is vault-wide: 300 s, every caller (ADR-093) | Window not extendable; ends on lock or policy change; owner's login never asked; only marked nodes ask | backend session | Per-node secret by ADR, #16, `2.0.0` | Standing, new |
| K-12 | GitHub CI has not run on this release (billing, #33) | Missing evidence, not a failure: local gates at `709840c` and the built-app sweep (§13) stand; nothing is published | operator | Closed 2026-11-01: repository moved to the FreexStudio organisation, `security.yml` and `build.yml` ran (PR #41) and read job conclusions; before publication | Open, new |
| K-13 | Dependabot: `glib` in the Linux desktop tree; 13 npm alerts patched in `b94443c` but not yet seen closed | Linux desktop only, none shipped; npm manifests are tooling and legacy V1 | backend session | `glib`: #15, `2.0.0`; npm: confirm closed after rescan, #14, before publication | Standing, new |
| K-14 | 5-minute idle lock and real sleep/screen lock not exercised by hand | Broker's own 15 min idle lock still applies; no change to any access decision | operator | #9, `2.0.0-beta.1`: run both, record in `RELEASE_VERIFICATION.md` §13 | Open, new |
| K-15 | Shared self-hosted runner on a shared host | Repository is private (no forks); runner is evidence, not a required context | operator | #6, `2.0.0-beta.1`: de-register or restrict before any public flip (#5) | Open, new |
| K-16 | Windows and Linux unsupported | Removes a platform; macOS unchanged | backend session (+ front-end team) | #29, `2.0.0`; release notes say "macOS only" | Standing, new |
| K-17 | A private-names node answers `entry_exists` to a guessed name | Names only; needs `create`; a miss leaves a visible entry | backend session | #35, `2.0.0-rc.1` | **New** |
| K-18 | `credmgr backup` is partial and nothing restores it | Vault untouched; copying vault and state directories is a complete backup | backend session | #36, `2.0.0-rc.1` | **New** |
| K-19 | A seed in an unrecognised shape is not protected until its owner types it | The owner's own seeds only; an agent cannot retype a seed away | backend session (+ front-end team) | #40, `2.0.0-rc.1` | **New** |
| K-20 | The source-available licence text (`LICENSE`, ADR-096) has not been reviewed by counsel, and governing law is not stated | The licence text only; no code path depends on it, and nothing is published | operator | Counsel review before the repository is made public | **New** |

**What this status does *not* claim:** that the backend is feature-complete (it is gate-complete
— K-3); that the desktop app has been checked on a real vault by a person (as of 2026-10-03 every screen
reads from the broker and every change goes to it — ADR-075 and the addendum above — but (when it was written) the result column of
`RELEASE_VERIFICATION.md` stays empty until someone fills it in); or that any of this has been exercised
against a real vault of real credentials. V2 creates its own vault and there is no migration, by design.

---

*Audited by the Phase 8 session, `2026-08-16`. Every number above was produced in that session;
none was carried over from `BUILD_LOG.md`. Where this report disagrees with an earlier claim,
this report ran the command.*

---

## 7. Final adversarial audit of 2.0.0-beta.1 — 2026-10-31

An independent agent on the strongest available model (Opus) audited commit `8d6a39d`, the release artefacts and the public export, read-only, assuming every claim false until reproduced. It found **1 P0, 2 P1, 5 P2, 6 P3**, and a re-verification round on `db50446` found the P0 not fully closed (two more doors, now closed) and one new P2; the P0 and P1-1 were reproduced on the real daemon. Its report is kept verbatim in `docs/release-verification/AUDIT_2026-10-31.md`; the table is the disposition.

| ID | Finding | Disposition |
|---|---|---|
| P0-1 | A stored TOTP seed reached any agent, MCP client or CLI caller through `entry.reveal` | **Fixed in two rounds**, ADR-094 item 1. Round 1 redacted the direct door; the re-verification then reproduced two others (an agent retyping the field with `field.update`, and seed shapes the inference did not recognise) and round 2 closed them with one seed class shared by reveal and `totp.code`, an owner-only retype away from it, and wider recognition. What stays open is K-19 (an unrecognised shape until its owner types it) |
| P1-1 | An approval was consumed by whichever caller asked first, for every field | **Fixed**, ADR-094 items 2 and 3; test `an_approval_is_taken_only_by_the_request_it_was_given_for`; K-7 (b) narrowed |
| P1-2 | `README.md` and `01_CONCEPT.md` said every node has its own 2FA gate | **Fixed** (the gate is vault-wide, K-11) |
| P2-1 | The public export failed `--strict` on this report's runner name (K-15) | **Fixed** (name removed) |
| P2-2 | The tarball's embedded notes said the CLI needs macOS 27.2 | **Fixed** by rebuilding the artefacts from the fixed tree |
| P2-3 | `RELEASE_VERIFICATION.md` marked idle and sleep lock as passed, against K-14 | **Fixed** (rows say "2026-10-18 build only; not re-run") |
| P2-4 | `privateNames` name-existence oracle | **Known risk K-17**, issue #35 |
| P2-5 | `credmgr backup` partial, no restore | **Known risk K-18**, issue #36; `RELEASE.md` now names the real backup |
| NEW-P2-a | The 512-slot approval cap could be used to evict and flood (the requester key included the live working directory) | **Fixed** (re-verification round; the key is node and token only; test `a_callers_subdirectories_are_one_requester`) |
| P3-1 | `graph.snapshot` says `enrolled` with no gate | Issue #37 |
| P3-2 | "Nothing is ever deleted" | **Fixed** (`v2/README.md`) |
| P3-3 | Doctor advised an unusable `rebuildRegistry` | **Fixed** (advice text) |
| P3-4 | Stale status line about the empty results column | **Fixed** |
| P3-5 | `release.sh --verify` weaker than it reads | Issue #38 |
| P3-6 | Authenticator code on argv | Disclosed in `SECURITY.md`; issue #39 |

**Re-verification round 2 (on `34542f8`, against the shipped binaries).** Every door the auditor re-tested is closed: an agent's retype of a seed field (over the socket and through the MCP tool) answers `capability_not_held`; grouped lower-case, 16-, 24- and 52-character seeds are typed as seeds, withheld from a reveal and served by `totp.code`; a flood of requests from 520 subdirectories leaves one pending request per node and a victim's request in another node stays decidable; the one documented residue (another tokenless process in the same node takes an approval for the same fields) reproduces as stated in K-7. The auditor's script for the remaining door-by-door hunt was stopped by its safety classifier, so those doors were not exercised by it: patching every field type, label, masked or value; `entry.update` with a field list; reorder or remove followed by undo; moving a value through another field; `=`-padded and Unicode look-alike seeds; eviction across nodes. They were handled here instead: every `type` value and `auto` on a seed field by a non-owner is refused, and a rename or an unmask leaves the seed withheld (`the_seed_class_is_one_class_and_an_agent_cannot_leave_it`); `entry.update` with a field list needs each field's value (`FieldReplace.value` is required), so an agent cannot carry a seed forward without already knowing it; an undo can only restore an earlier state, and an agent cannot create a worse earlier state; a padded seed is in K-19; eviction needs more than 512 requesters, and a requester is a node plus a token. These are reasoned and tested, not re-audited by an independent agent.

**Checked and found true by the audit:** both `SHA256SUMS` lists; minimum macOS 13.1 in every binary; ad-hoc signing and Gatekeeper refusal; no home or cargo paths in the binaries; reproducible build to within the UUID and signature; 905 tests in 59 binaries listed; the isolation suite, root-key rotation, name caps, approvals and seal durability tests; 55/55 broker operations and 243 matrix rows with no plaintext on disk; 25 error codes; 15 MCP tools; the desktop CSP, token custody and 11 storage keys; neither `audit-probe.js` nor a supporter code in the export. **Not checked by the audit:** the desktop unit, e2e and real-daemon suites, a launch of the built app, the same-checkout rebuild, the full 25-minute suite; CI and the idle and sleep timers were excluded by instruction (K-12, K-14).
