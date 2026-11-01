---
id: V2-022
classification: public
title: Organisation vault, sync and licensing
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-18
---

<!-- artifact-hardened: NEEDS RE-HARDENING — rewritten from Pass 1 to a resolved target design on
     2026-08-18 (Session 21). Every one of the five Pass-1 proposals carried a `needs-revision`
     verdict; each is now decided, with the reasoning stated. Nothing here is built, and §4 marks
     every part of it `planned`. One product-positioning decision (§3) is deliberately left to the
     operator and is a gate on implementation, not on this design. Updated 2026-09-24 for
     ADR-065 (the owner's login reaches every node but Orphaned). Updated 2026-10-02 for ADR-074
     (MIT for everyone, organisations included: §4.4 rewritten to the optional commercial-licence
     certificate; §1, §2.4, §2.9 and §2.10 annotated as superseded where they predate it). -->
> **Licence update, 2026-10-31 (`ADR-096`, supersedes `ADR-074`):** CredMgr is source-available under the FreexStudio Source-Available Licence 1.0 (`LICENSE`), not MIT. Wherever this document says "MIT" it records the earlier decision and is kept as history; the licence in force is the one in `LICENSE`.

# Org Vault: hierarchy, pairing-code sync, retention/purge rules, and licensing (MIT; an optional commercial-licence certificate)

`CredMgr V2` · the organisation product: hierarchy, vault-to-vault sync, retention, and licensing · `2026-08-18`

> **Status.** **Nothing in this document is built.** No organisation vault, no sync process, no
> licensing check, and no line of code for any of them exists in `v2/crates/**`. What this
> document now contains is the complete target design, with every Pass-1 open question resolved
> and the reasoning recorded. §1 preserves the operator's requirements verbatim and §2 the
> source-verified corrections; both are records and are unchanged. §3 names the one decision that
> is the operator's rather than this design's, and §4 is the resolved specification.
>
> **Licensing was settled on 2026-10-01 (`ADR-074`): CredMgr is MIT for everything and everyone,
> organisations included, and nothing in the product is gated by payment.** The payment-derived
> licence number, the tier encoding and the "a licence gates organisation features" rule that
> earlier drafts of this document designed are withdrawn. §4.4 now states only what survives — an
> *optional* commercial-licence certificate — and §1, §2.4, §2.9 and §2.10 carry a note wherever
> they predate that decision. They are otherwise unchanged records.

---

## 0. How this file was built, and what "not hardened" means here

**What changed on 2026-08-18.** §3 and §4 were rewritten from proposals into decisions. The
history below describes how the Pass-1 material was produced and is kept because the verifier
findings it records are the reason several of those decisions went the way they did.

A 14-agent workflow (2026-08-10) did two things before any design was written: (1) four agents
read the actual V2 source and docs to ground every claim below in what the code and design
corpus really say today, not what any prior document *claimed* it says — this caught real
errors, listed in §2; (2) five design proposals (one per topic) were each independently
adversarially verified by a second agent instructed to find contradictions, unsupported
assumptions, and invariant conflicts. **Every proposal came back `needs-revision`** — none were
rejected outright, but none are ready to implement as written. This file preserves both the
proposals and the verifier's findings, because the disagreements and gaps are exactly what the
next session needs, not noise to clean up before handoff.

**Do not skip §2.** Every proposal in §4 depends on it, and at least three requirements in §1
cannot be correctly implemented without the corrections in §2.

---

## 1. Requirements, verbatim (operator, live chat, 2026-08-10)

Captured in full, unedited, so nothing gets softened or lost in paraphrase. Organized under the
topic each piece belongs to — order matches how the operator raised them, not a priority ranking.

**Org hierarchy:**
> "In the org version, they get to choose the Main Vault Owner (can be CEO, Project Manager, ...). It defines its vault as the mother vault and can define different departments and make each department have access to a defined number of credentials... the org should have an additional page where they get to define the company layers, from the Main vault to different departments. As in the entry system, the Main vault holder can choose who can access which credentials, which project, and which layer."

**Sync connection:**
> "I want this feature added... not a full-time sync, but a built-in vault connection that, when clicked by both users (User 1 and User 2) or the whole company, creates a connection system where they can be synced... define a system and interval sync or manual sync, all built in. The CEO makes the Linux node available to all the vaults that are opened by a license. Then, when the sync system is set, the vault should create a number that both users get to enter, and they are then connected. The Linux department could update the creds as they change."

**Deletion / changelog rules:**
> "One important thing is that the main vault 7-day delete should change to 30 days (or change as the user sets). But if a cred gets deleted by a downstream user, only the downstream and that vault get their change log cleared. To fully clear the change log, only bo[ss] gets to do it. Set some rules for lite and some for pro."

**Product split:**
> "The org vault is different from the personal vault. The org should download the org version, and personal should download the personal version."

**Licensing / activation:**
> "The org vault only opens after the payment is accepted, received, and sent back by the dev team, meaning they should send the money to the wallet. Send the transaction hash and a screenshot of the payment to the project email address, [the project's billing address — redacted for publication; it is operator-held and is deliberately not recorded in this repository]. And within 24 hours they would receive their license number. The license number should be an offline decryption code, created by the dev team, based on the amount they paid. And the license decryption system should be offline. Let the claude oppus think and create the best approach here, how to create the license number offline and based on the amount they paid."

> **Superseded 2026-10-01 — `ADR-074`.** The licensing / activation requirement quoted above (the
> organisation vault opening only after a payment, a licence number derived from the amount paid)
> is retired: CredMgr is MIT for everyone and nothing opens or locks on payment. The quotation is
> preserved unedited as the operator's record of 2026-08-10; §4.4 states what replaced it.

**Open scope:**
> "Add some org features if there's more to be added."

**Explicit instruction on how much to resolve now:** the operator wants this recorded and
researched, with Opus making the actual final design calls next session — not fully resolved by
this pass. That instruction is honored throughout §4: candidates and directions are proposed,
none are declared final.

---

## 2. Ground-truth corrections — read before touching any proposal below

These came directly out of source verification (`crates/core`, `v2/docs/*`) and adversarial
review. Several contradict assumptions a first-pass reading of the requirements would naturally
make — including assumptions the first-draft proposals themselves made and had to be corrected on.

1. **Node depth is hard-capped at 2, not open-ended.** GLOBAL (depth 0, singular, unrenamable) →
   project (depth 1) → sub-node (depth 2). Creating a child of a depth-2 node is rejected at the
   API. This is deliberate (D-03, `01_CONCEPT.md:119`): "unbounded depth makes the access matrix
   unreasonable to audit." **The operator's "company layers, from the Main vault to different
   departments" (plural, open-ended) does not fit an arbitrary-depth org chart as architected.**
   Two levels are available: Department (depth 1) and Team (depth 2). Either the UI caps
   "layers" at exactly these two, or D-03 gets reopened for an org tier — an explicit tradeoff
   the operator needs to make, not something to default silently.

2. **"Linux" in the existing docs/README is a plain illustrative example name, not a reserved
   or special node.** It shows up as one of several example depth-1 projects (alongside A/B/C/D)
   with `dev`/`staging`/`prod` sub-nodes, used to illustrate the "a parent doesn't automatically
   read a child's contents" rule (D-01). It is not a system concept. **The operator's phrasing
   ("The CEO makes the Linux node available to all the vaults... The Linux department could
   update the creds") most likely means "a department" — using the docs' own recurring example
   name coincidentally, not a request for a specific reserved node called Linux.** Flagged so
   Opus doesn't chase a nonexistent special-node concept; confirm the intended meaning with the
   operator if still ambiguous.

3. **V2 is single-user, single-machine, enforced at the transport layer today — not just a
   policy statement.** `LOCAL_PEERCRED` (the Unix-socket peer-credential check) rejects every
   OS user ID except the one that created the vault, `05_THREAT_MODEL.md` §5. This means even a
   **second human on the same physical machine, different OS account,** is rejected today — a
   stricter bar than "single company, multiple laptops" might suggest. True multi-person access
   to one running broker does not exist in any form currently.

4. **The README states, explicitly and by name, that CredMgr is "Not a multi-user sync tool" —
   architectural, not a licensing gate** (`README.md:115-118`): "no real-time sharing between
   teammates' vaults... an organization's developers can each run their own instance under one
   commercial license... they just never sync with each other." **The requested sync feature is
   a genuine reversal of this stated claim, confirmed by adversarial review, not a permitted
   reading of it.** See §3 — this needs an explicit operator decision to proceed, and the
   README/threat-model text must be rewritten if it does, not left standing alongside a shipped
   sync feature. *(Superseded in part, 2026-10-01 — `ADR-074`: "under one commercial license"
   quoted the retired Personal & Commercial Use License; under MIT no licence is needed to run one
   instance or many. The architectural claim itself — single-user, single-machine — is unchanged,
   and `README.md` here means the repository-root README, whose License section is now MIT.)*

5. **A-1 ("the vault process makes no outbound network connection, ever") is scoped specifically
   to the `credmgrd` broker binary** — CI-verified by scanning that binary for zero references
   to `reqwest`/`hyper`/`curl` (`17_AIRLOCK_AND_LLM.md:35`). A feature living in a genuinely
   separate process that never links into `credmgrd` and holds no key material can satisfy A-1's
   literal text. This is the mechanism the sync proposal below leans on — but see §3 for why
   satisfying A-1's letter doesn't resolve the README conflict in item 4.

6. **`crates/core` has NO ed25519/EdDSA (asymmetric signing) — only X25519 (key agreement/AEAD)
   and a separate HMAC-SHA256 symmetric scheme.** `POST_LAUNCH_ROADMAP.md`'s existing claim that
   CredMgr "already has the primitives" for offline-signed licenses via "X25519/ed25519
   machinery" is **factually wrong** — confirmed by `grep -rni 'ed25519|eddsa' crates/core/`
   returning zero matches, and by `Cargo.toml` listing no signature crate. Any ed25519-based
   licensing design (the strongest candidate in §4.4) requires adding a new dependency, not
   wrapping existing code. `POST_LAUNCH_ROADMAP.md` should be corrected to stop citing this as
   already-available.

7. **V2's actual audit-log retention is 12 months, not 7 days** (`v2/docs/03_DATA_MODEL.md §9`:
   "Rotated monthly, kept 12 months, purgeable by the human only... 2FA-gated"). **The "7 days"
   figure that exists in the design corpus is a completely different mechanism: the soft-delete
   *recovery/undo* window** for an individually deleted credential (`entry.remove`/`entry.undo`),
   and it is stated as an absolute constant — `10_API_AND_MCP.md §3.2`: "No audit purge, no
   recovery-window shortening... The 7-day window and the log cannot be erased by anything that
   runs unattended," and `18_ENDPOINT_INDEX.md §1.6`: "not user-shortenable." **The operator's
   "main vault 7-day delete should change to 30 days" almost certainly refers to the recovery
   window (a deleted credential stays undoable for 30 days instead of 7), not the 12-month audit
   log** — but this needs an explicit operator confirmation, because as currently designed the
   recovery window is stated as a fixed constant that nothing can shorten *or* lengthen without
   its own new mechanism. A first-draft proposal conflated these two numbers; do not repeat that.

8. **GLOBAL-Admin does not automatically reach every descendant node's grants or data** — this
   was explicitly designed and re-confirmed multiple times (ADR-047, reaffirmed by ADR-050):
   "there is, by design, no scope shaped like Global-reads-descendants." **"Only the boss gets to
   fully clear the changelog" cannot be implemented as "GLOBAL-Admin reaches into every node" —
   that specific reach pattern has already been deliberately rejected in this codebase.** A
   vault-wide purge authority needs a different justification (e.g., "the audit log itself is a
   vault-root artifact with no per-node owner," not "GLOBAL admin reaches down").

9. **Per the actual UI/UX spec table (`09_UI_UX_SPEC.md §5`), node hierarchy and grant
   view/revoke already exist in *both* Lite and Pro** — "a Lite user's vault is byte-identical to
   a Pro user's... switching is instant, non-destructive, and never hides data — only controls."
   Only grant *creation*, node *policy* controls, and the audit-log/Operations-panel UI are
   Pro-exclusive. A first-draft proposal justified gating org features to Pro on "Lite has no
   node hierarchy" — that reasoning is wrong; if org features are Pro-gated, it must be argued on
   different grounds (most likely: they're a separate paid org license, not a Lite/Pro toggle at
   all — see open question in §4.4). *(Superseded 2026-10-01 — `ADR-074`: no payment gates any
   feature, so organisation features are not gated by a licence at all, Pro or otherwise.)*

10. **No ADR anywhere in `14_DECISIONS.md` touches licensing, signed-artifact verification,
    retention-policy configuration, or purge scoping.** Everything in §4 is genuinely
    greenfield — there is no existing decision to defer to, but also none to contradict by
    choosing a new direction. *(Corrected 2026-08-17: at the time this section was written,
    the corpus ran ADR-001 through ADR-052, 1,424 lines, with ADR-053 next available — since
    then ADR-053 landed as the Phase 8 audit's `node.restore` fix, unrelated to org vault, and
    ADR-054/055 landed as the Backend-finish session's `maintenance.*`/`entry.undo` work. The
    corpus now runs ADR-001 through ADR-055, 1,850 lines. Next available ADR number:
    **ADR-056.***) *(Re-measured 2026-10-02: the corpus runs ADR-001 through ADR-077; ADR-078 and
    ADR-079 are reserved for the field model and the K-7 orphan key, so the next unreserved number is
    ADR-080. `ADR-074` is the decision that touches licensing.)* *(Re-measured 2026-10-03: ADR-078 and
    ADR-079 are decided — the field model and K-7 — and the corpus runs ADR-001 through ADR-079; the next number is
    ADR-080.)*

---

## 3. The one decision that is the operator's, not this design's

**Does shipping vault-to-vault sync knowingly reverse the product's "not a multi-user sync tool"
claim, or should the feature be dropped to keep that claim true?**

This is a product-positioning decision with a public consequence, and it is deliberately not
resolved here. Two independent adversarial reviews converged on the same finding: reading "no
*real-time* sharing between teammates' vaults" as implicitly permitting non-real-time sharing is a
strained reading. The surrounding sentence's actual claim is single-user, single-machine, and the
parenthetical exists to clarify that the restriction is architectural rather than a licensing
trick — not to carve out an exception for slower sync.

**What this design commits to, either way.** The mechanism in §4.2 is specified completely and can
be built the day the decision goes one way. But it is presented as a **new capability, not a
reinterpretation of an old claim**: today nothing about CredMgr can move data over a network under
any circumstance, by construction. A sync feature, however well isolated, changes that. "We did not
violate A-1's literal text" is a narrower statement than "we did not change what this product
does", and only the first is true of any sync design.

**Therefore, shipping §4.2 is gated on three things happening together**, and this document treats
them as a single atomic change: the operator's explicit decision; a rewrite of `README.md`'s "not a
multi-user sync tool" section and `05_THREAT_MODEL.md §5`'s "explicitly out of scope" framing to
say what is then actually true; and the release note presenting sync as an added capability. A
shipped sync feature standing next to an unchanged README is the failure mode this gate exists to
prevent — a user discovering the contradiction after the fact is worse than never shipping it.

**Recommendation, stated so the decision has a default:** ship it, and rewrite the claims. The
requirement is real and repeatedly stated by the operator, the isolation design in §4.2 keeps the
guarantee that actually matters (no key material ever reaches the network-capable process), and a
product claim that has to be defended by a strained reading of its own parenthetical is not worth
keeping.

---

## 4. The resolved design

Everything in this section is **`planned`**. None of it exists. Each subsection states the
decision, why the Pass-1 proposal needed revising, and what the finished thing is.

### 4.1 Organisation hierarchy — **`planned`**

**Decision: keep the depth-2 cap (D-03) unchanged. An organisation is expressed as GLOBAL →
Department → Team, and anything deeper is expressed with grants rather than nesting.**

The Pass-1 proposal contemplated reopening D-03 to allow an arbitrary-depth org chart, because the
operator's requirement says "company layers" in the plural and open-ended. That is the wrong trade,
and the reason is in D-03's own justification: unbounded depth makes the access matrix unreasonable
to audit. An organisation vault is precisely the setting where auditability matters most — the
whole product claim is that an owner can answer "who can reach this credential" — so the one place
D-03's cost is highest is the place its benefit is highest too.

The requirement is satisfiable without depth. The access graph already supports grants between any
two nodes (`06_ACCESS_GRAPH.md §1`, rule R7), and a real organisation is a matrix rather than a tree: a
platform engineer who needs one credential from Finance is modelled far better by a grant than by
being relocated in a hierarchy. So:

| Org concept | V2 node | Depth |
|---|---|---|
| The organisation itself | `GLOBAL` | 0 — singular, unrenamable, owned by the Main Vault Owner |
| Department (Engineering, Finance, Operations) | project node | 1 |
| Team or environment within a department | sub-node | 2 |
| Anything more specific, or any cross-department access | a **grant**, not a node | — |

**The Main Vault Owner** is the subject holding `Capability::Admin` scoped to `GLOBAL`. That role
already exists and needs no new concept: per `ADR-056`, a real unlock mints exactly such a token,
and per `06_ACCESS_GRAPH.md`'s R2, it is the only scope that can administer the root. Since
`ADR-065` that login is evaluated as each target node, so it also reaches and administers every
department beneath the root — every node but Orphaned — without a grant.

**What must be built:** a department-shaped view over `graph.snapshot` (the data already exists);
`node.create` gaining an org-aware naming policy; and an owner-only screen for issuing and revoking
grants in bulk, since doing it one grant at a time does not scale past a small team.

### 4.2 Vault-to-vault sync — **`planned`**, and gated on §3

**Decision: a separate `credmgr-syncd` process, pairing-code enrolment, ciphertext-only transfer,
and no key material on the network side — ever.**

The Pass-1 architecture (isolate outbound capability into a process that never links into
`credmgrd`) survived review and is kept. What needed revising was the claim that this preserves the
product's existing guarantee; §3 handles that honestly instead.

**The mechanism, end to end.**

1. **Enrolment.** Both vault owners will open the pairing screen. One vault will generate a short
   human-transcribable pairing code; the other will enter it. The code will authenticate an X25519 key
   agreement between the two vaults, so it must be short-lived, single-use, and rate-limited — the
   same properties `07_TWO_FACTOR.md §4` already requires of recovery codes, and the same backoff
   (`auth_backoff.rs`) will apply.
2. **What crosses the wire.** Envelope ciphertext for a specific node, and nothing else. A synced
   entry will be re-sealed to the *receiving* vault's node key before transfer, which means
   `credmgr-syncd` handles bytes it cannot open. This is the property that makes the isolation real
   rather than procedural: compromising the network-facing process yields ciphertext, not secrets.
3. **Direction.** Push-only, per node, per pairing. The department that owns a credential will
   publish it; a receiving vault will never reach into a sender. This removes an entire class of
   authorisation question and matches the operator's own description — a department updating the
   credentials it owns as they change.
4. **Cadence.** Manual by default, with an optional interval. Never continuous: a background
   process holding an open network connection to a credential vault is a materially different
   security posture from one that connects, pushes, and exits.
5. **Process boundary.** `credmgr-syncd` will be a separate binary that does not link
   `credmgr-keystore` or `credmgr-core`'s key material paths at all, so A-1's CI check
   (`17_AIRLOCK_AND_LLM.md §1`) continues to pass against `credmgrd` on its own terms rather than
   by exemption.

**What this design does not do:** conflict resolution beyond last-writer-wins per entry, real-time
propagation, or any form of central server. Each is a deliberate omission, and each would need its
own decision.

### 4.3 Retention, deletion and purge scope — **`planned`**

**Decision: separate the two windows that Pass 1 kept conflating, and scope purge authority to the
node.**

The verifier's most substantial finding was that this proposal treated one mechanism as two and two
as one. The corrected model, consistent with `03_DATA_MODEL.md §9`:

| Mechanism | Today | Org target |
|---|---|---|
| **Soft-delete window** (a removed entry is recoverable) | 7 days, fixed | **30 days by default**, org-owner-settable 7–90 |
| **Audit log retention** (the hash-chained record) | 12 months, rotated monthly | **unchanged at 12 months** |
| **Audit purge** | human only, 2FA-gated | **scoped**: a department owner purges their own department's segment; only the Main Vault Owner purges the root |

The operator's requirement — "if a cred gets deleted by a downstream user, only the downstream and
that vault get their change log cleared; to fully clear the change log, only the boss gets to do
it" — is exactly this scoping rule, and it falls out of the access graph rather than needing new
machinery: purge resolves `Capability::Admin` against the node whose segment is being purged.

**The constraint that cannot bend:** the audit log is hash-chained, so a purge truncates a segment
at a boundary; it never deletes a record from the middle. Deleting one record from a chained log
breaks verification for every record after it, which is why `18_ENDPOINT_INDEX.md` records
`DELETE /api/changelog/:id` as removed with no V2 successor.

### 4.4 Licensing — **`planned`** (the optional part only). MIT for everyone; a commercial-licence certificate is optional

**Decision (operator, 2026-10-01; `ADR-074`): CredMgr is MIT for everything and everyone,
organisations included, and nothing in the product is gated by a licence, a payment or a key** —
not the organisation vault, not sync, not Pro. This section used to design the opposite: a
payment-derived licence number, tiers encoded in an Ed25519-signed payload, and "a licence gates
organisation features only". All of that is **withdrawn**. What remains is one optional artefact.

**What survives: an optional commercial-licence certificate.** An organisation whose procurement
needs a paid agreement — an invoice, a written licence certificate, priority support — can arrange
one through freexstudio.com. What it receives is a *document*, not a switch.

- **Issued by hand, against an invoice.** There is no payment flow in the product, no licence
  server, no activation step and no place to type a key. The product never learns whether an
  organisation holds a certificate.
- **If the certificate is a signed file, the primitive is Ed25519.** A procurement team can then
  verify it offline against a published public key. The reason `ADR-074` keeps from the earlier
  design is the one that still holds: an HMAC verifier is also a forger (§2.6;
  `04_CRYPTO_AND_KEYS.md §1.1`), so a symmetric scheme proves nothing to a third party. The private key lives offline, never on a build machine,
  in CI, or in this repository; the shipped product, if it verifies a certificate at all, holds
  only the public key.
- **Nothing in the application depends on it.** If a later release shows a certificate under
  `Settings → About`, its absence, expiry or a failed verification changes nothing the application
  does, and the check is made by the application shell, never by the broker, with no network call
  (`05_THREAT_MODEL.md §9.4`; A-1 is unchanged).
- **No machine binding, no revocation promise.** A binding would contradict §2.4's model of each
  developer running their own instance, and A-1 rules out live revocation. A certificate states
  an agreement; it does not grant or withdraw a permission, because MIT already granted it.

**The open questions Pass 1 reserved, as they now stand:**

| Question | Answer |
|---|---|
| One install or many? | **Many.** MIT covers every install; a certificate states an agreement, not an install count. |
| Revocation? | **None, and nothing to revoke.** A certificate gates nothing. |
| Does a licence gate Pro mode, or anything else? | **No.** Lite/Pro (`ADR-031`, `09_UI_UX_SPEC.md §5`) is a free, instantly reversible control-surface mode, and no organisation feature is gated either. |
| Where does a signing key live? | **Offline, in the maintainer's own vault.** Never on a build machine, never in CI, never in this repository. Issuing a certificate is a deliberate manual act. |

**Withdrawn by `ADR-074`, listed so a reader of an older draft knows what no longer applies:** the
payment-evidence-to-licence-number issuance flow; the mapping from an amount paid to a tier; a
licence payload carrying a tier; and any rule under which an organisation feature is unavailable
without a licence.

### 4.5 Additional organisation features — **`planned`**

Kept from Pass 1 with the two features the verifier flagged for overstating existing primitives now
corrected: neither an organisation-wide audit export nor any signed attestation of vault state can
reuse "existing signing machinery", because there is none (§2.6). Both depend on a signature
dependency that does not exist in `crates/core` today — Phase 11's release signing introduces one
(`12_BUILD_PLAN.md §5.3`) — and neither should be scheduled before it lands.

---

## 5. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `01_CONCEPT.md §3` | D-03, the depth-2 cap that §4.1 declines to reopen |
| depends on | `06_ACCESS_GRAPH.md §1`, `§6` | the R7 grant rule and the propose/confirm/active/expire/revoke lifecycle that express org structure the hierarchy deliberately cannot |
| depends on | `03_DATA_MODEL.md §9` | the 12-month audit retention §4.3 leaves unchanged, and the chain property that bounds purge |
| depends on | `17_AIRLOCK_AND_LLM.md §1` | A-1, the no-outbound-network rule §4.2's process boundary is designed around |
| depends on | `04_CRYPTO_AND_KEYS.md §2` | the absence of any signing primitive, which decides §4.4 |
| feeds | `05_THREAT_MODEL.md §5` | the "single-user, single-machine" framing that §3 gates on rewriting |
| depends on | `14_DECISIONS.md` | `ADR-031` (Lite/Pro is a free mode — nothing may gate it), `ADR-056` (the Main Vault Owner token §4.1 relies on), `ADR-074` (MIT for everyone; §4.4's licensing is an optional certificate and gates nothing) |

## 6. Source

**Requirements.** §1, verbatim operator chat, 2026-08-10. Preserved unedited as a record.

**Ground truth.** §2, produced by source verification against `crates/core`, `crates/brokerd` and
the corpus, and re-checked on 2026-08-18: `crates/core` still contains no ed25519 or EdDSA of any
kind, and audit retention is still 12 months.

**Code.** None. This document describes nothing that exists; every subsection of §4 is marked
`planned` for that reason.

**Decisions recorded here rather than as ADRs.** §4.1–§4.3 and §4.5 are design content of this
specification, not cross-cutting architectural decisions, and none of them changes anything built.
They become ADRs at implementation time, when they start constraining code. The exception is
licensing (§4.4): it changed the repository's licence posture rather than this design alone, so it
is recorded as `ADR-074` (2026-10-01) and §4.4 only states its consequence here.

**Figure.** `org-hierarchy-vs-grants` (§4.1) — `docgen`, `kind: "system_map"`. Spec:
`v2/docs/22_ORG_VAULT_SYNC_AND_LICENSING_spec.json`. Depth/cap facts cited from
`01_CONCEPT.md` D-03 and `03_DATA_MODEL.md §2`; the grant edge from `06_ACCESS_GRAPH.md §1`
R7. The organisation drawn (`example.com`, "Engineering"/"Finance") is illustrative and
generic, not a real company.

<!-- figure:org-hierarchy-vs-grants -->

Depth carries the org chart's ownership skeleton — GLOBAL → Department → Team, hard-capped at
depth 2 (D-03) — while a grant (R7) carries everything a tree can't: a cross-department access
is one edge, not a relocated node, and a deeper layer is rejected outright rather than modelled.
