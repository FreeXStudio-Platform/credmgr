---
id: V2-011
classification: public
title: Migration
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-09-13
---

<!-- artifact-hardened: NEEDS RE-HARDENING — rewritten to ultimate-destination state on
     2026-08-18 (Session 21). The previous stamp (Approved @ 9e0937e) still resolved, and this
     rewrite invalidates it by construction, because the body changed. Every claim below was
     checked against live source in this pass — including the two that the previous version
     stated in the present tense while nothing implemented them (`credmgr import`, and the
     short-name alias). The corpus-wide hardening stamp is the operator's to assign after their
     own review, not this session's to self-award.

     Verification-backlog pass, same day (`VERIFICATION_BACKLOG_S21.md`, `11_MIGRATION.md`
     section): eight further false claims and three convention violations were re-derived from
     live source and fixed. §1's "a user installs V2, runs first-run setup" and its first-run
     store-location paragraph — both present tense for an unbuilt bootstrap — corrected to future
     tense with the gap stated plainly: no `init` subcommand exists, and no code path writes a
     vault tree outside a test fixture. §2's "V2 vault that starts empty" row narrowed to what is
     actually `built` — path resolution only — with two new `planned` rows added naming the
     missing bootstrap and the missing runnable broker directly; the "manual carry" row corrected
     from `built` to `partial` for the same reason. §4's and §3.2's notes about `03_DATA_MODEL.md` and
     `09_UI_UX_SPEC.md` still carrying retracted migration language were themselves stale — both
     documents had already self-corrected in the same session — and are now recorded as fixed
     rather than open. §6 downgraded from `built` to `partial`: the V1→V2 pipe cannot execute end
     to end today because no shippable process ever serves `<vault>/run/broker.sock`
     (`server::run` has three callers in the whole workspace, all test fixtures). §8's Connections
     row no longer claims an inbound `03_DATA_MODEL.md` reference to this document's §4 that does
     not exist — that document cites this one whole. §9's verification recipe for the 19 CLI arms
     is now scoped to the top-level match block (an unscoped grep over the whole file returns 26),
     and its `corpus_check crossrefs` claim — which checks `## Connections` citations, not
     cross-document prose references — is corrected to say what the tool actually checks.

     Verification-backlog round 2, 2026-08-19 (`VERIFICATION_BACKLOG_S21_ROUND2.md`,
     `11_MIGRATION.md` section): three further defects re-derived from live source and fixed. §8's
     Connections row wrongly said `18_ENDPOINT_INDEX.md §2` enumerates both `migrate` and `import`
     as absent from the CLI surface — that section actually lists `import` under "Carried unchanged
     (28)", i.e. present, and marks only `migrate` as removed; the row now cites each command's
     real disposition there. §9's account of the unscoped-grep overcount wrongly attributed the
     line-249 `"verify"` arm to both `cmd_doctor` and `cmd_gate` — it belongs to `cmd_gate` alone,
     since `cmd_doctor` dispatches by boolean flag, not by a matched subcommand string. §9's
     description of `corpus_check crossrefs` — itself a round-1 fix — was still wrong in the
     opposite direction from the original defect: it said the tool checks only `## Connections`
     table citations, when in fact `check_crossrefs()` regex-scans a document's entire prose body,
     so it does see stray cross-document citations wherever they sit; what it still cannot do is
     confirm a cited section is actually about the claim (this backlog's dominant defect class), or
     see `v2/CHANGELOG.md` at all, since that file sits outside the `v2/docs/` directory the tool
     globs.

     Falsehood pass F2, 2026-09-13: this document was written while vault bootstrap and a runnable
     broker did not exist, and said so — correctly — in five present-tense places (the Status
     block, §1's two paragraphs, §2's bootstrap and `credmgrd` rows, §5's and §9's subcommand
     counts, and §6's opening). `ADR-061` (2026-08-31, `b43e1d7`) built both: `credmgr init` exists
     and works, and `credmgrd`'s `main()` calls `server::run` on `<vault>/run/broker.sock` instead
     of printing one status line and exiting. Every one of those claims has been rewritten to the
     built state, the two `planned` table rows flipped to `built`, the "manual carry" row and §6
     from `partial` to `built` (with the one thing still unproven — the V1→V2 join, which no test
     can exercise without a vendored V1 — stated rather than dropped), and the counts corrected:
     19→20 top-level CLI subcommands (`init` at line 45, so the scoped range is now `45,64p` and
     the unscoped arm grep returns 27), 397→406 tests across 33→35 binaries. Prior dated figures
     are kept in place beside the new ones, never overwritten. Not touched, because they are dated
     records of what a pass found on its own date and not live claims: every paragraph of this
     comment above this one. Updated 2026-09-24 for ADR-073 (the broker op `credmgr import` will
     call, `entry.create_batch`, exists in a single-value form; the command still does not, §5). -->

# Migration — V2 ships empty, and there is no import from V1

`CredMgr V2` · the decision not to have a migration, and everything that follows from it · `2026-09-13`

> **Status.** The decision is **in force and verifiable in code**: `grep -rni "migrat"` over
> `v2/crates/**/*.rs` returns nothing, the CLI's 24 top-level subcommands include no `migrate`
> (its one `import` reads `.env` text and nothing else, §5), and no crate contains a reader for any
> V1 file format. One thing this document describes is still **not built**: the short-name alias
> display of `ADR-032` (§4); `credmgr import` for `.env` files (§5) is **built** as of 2026-10-02,
> without the preview and the collision options its target design lists. Vault bootstrap and first-run setup (§1) **are**
> built, as of `ADR-061` (2026-08-31, `b43e1d7`): `credmgr init` creates a vault, and `credmgrd`'s
> `main()` resolves the vault path and serves `<vault>/run/broker.sock` instead of printing one
> status line and exiting. That closes both gaps the "manual carry" path §6 depended on — there is
> now a vault for the write to land in and a shippable process for `credmgr set` to reach, so the
> two independently real commands (a V1 `get` that writes to stdout, a V2 `set` that reads from
> stdin) can actually be joined. Earlier revisions of this block said the opposite in the present
> tense; they were true when written and false from 2026-08-31 onward. Section 2 is the honest
> table; `## Source` is where each row can be re-checked. Since `ADR-063` (2026-09-24) that
> daemon also opens an existing vault on a passphrase unlock and writes every change through to
> disk, so a value carried in by hand (§6) survives a broker restart.

---

## 1. The decision

**V2 ships empty. It does not import from V1. There is no migration, no dry run, no parallel
window, no cut-over, and no retention clock.**

A user installs V2, runs first-run setup, creates nodes, and adds their own credentials. That is
the whole story, and first-run setup is **built** as of `ADR-061` (2026-08-31, `b43e1d7`).
`credmgr init` is one of the CLI's 24 top-level subcommands; it drives the broker's
`vault.init_begin` / `vault.init_confirm` ops, writes the vault tree and root wrap, and prints a
one-time recovery code the user must retype before anything is committed
(`crates/cli/src/main.rs::cmd_init`). `credmgrd`'s `main()` resolves the vault path, creates
`run/`, and serves the socket (`crates/brokerd/src/main.rs`) — until 2026-08-31 it printed one
status line and exited, which is what earlier revisions of this paragraph described. A first run
now happens on disk.

"Empty" is literal, and it has a location. `default_vault_dir()`
(`crates/store/src/paths.rs`) computes where the store lives —
`Library/Application Support/credmgr` on macOS, `%APPDATA%\credmgr` on Windows, the XDG data
directory elsewhere, or wherever `CREDMGR_VAULT_DIR` points, which is the override the test suite
and any packaging script use — and two code paths now act on that result rather than only
returning it: `credmgrd`'s `main()` creates `run/`, and the init ops write the vault itself. The
broker's socket is `<vault>/run/broker.sock` inside that directory. Nothing is read from anywhere
else at first run, and in particular nothing is read from a V1 vault — `cmd_init` takes a
passphrase and a recovery-code confirmation from stdin, and the only path it inspects is the
destination's own (`is_inside_git_working_tree`, which refuses to create a vault inside a checkout).

**Why the product is shaped this way.** V2 is a program other people install. It is not the
maintainer's own vault wearing a new coat. V1 remains a working, published Node product with its
own tests and its own users; the maintainer's live V1 vault stays on V1, where it works, and is
not this project's concern. Once that is stated plainly, every migration feature loses its
justification at the same moment — because each of them existed only to serve the assumption that
V2's job was to *become* one specific existing vault.

**The invariant this produces**, and the reason the decision is worth stating as strongly as it
is: no V2 code path opens a V1 file. Not read-only, not behind a flag, not in a test fixture. An
import path that exists but is disabled is still an attack surface, still a maintenance burden,
and still a thing a future session can be talked into enabling. Absence is the strongest form of
the guarantee, and it is the form that can be checked with a grep.

## 2. What exists today

The corpus status vocabulary (`ADR-059`) is `built` / `partial` / `planned`. This document needs
one more word, borrowed from `18_ENDPOINT_INDEX.md`'s row legend: **`removed`** — designed once,
deleted deliberately, and not on any roadmap. A `planned` row will exist one day; a `removed` row
will not.

| Thing | Status | Evidence |
|---|---|---|
| Path resolution for where a V2 vault will live, at a platform default path or `CREDMGR_VAULT_DIR` | `built` | `crates/store/src/paths.rs` — `default_vault_dir()`, and its `vault_and_state_dirs_never_coincide` test |
| Vault bootstrap / first-run setup — actually creating that vault | `built` | `ADR-061` (2026-08-31, `b43e1d7`): `credmgr init` (`crates/cli/src/main.rs::cmd_init`) drives the broker's `vault.init_begin` / `vault.init_confirm` arms. Proven on disk by `crates/brokerd/tests/vault_init.rs::begin_then_confirm_writes_a_vault_a_separately_keyed_broker_can_unlock`, and over a real socket with the real binary by `crates/cli/tests/vault_init.rs::init_over_the_real_binary_and_socket_creates_a_vault` |
| A `credmgrd` that serves `<vault>/run/broker.sock` outside a test | `built` | `crates/brokerd/src/main.rs` — `main()` creates `run/`, then calls `server::run(state, &paths.run_socket())`; since `ADR-063` its `vault.unlock` opens an existing vault from disk and every change is written through (`crates/brokerd/tests/durable_vault.rs`). `grep -rn "server::run" v2/crates --include='*.rs'` now matches that real call site plus four test fixtures (`broker_integration.rs`, `success_criteria.rs`, `vault_init.rs`, `mcp_integration.rs`), two doc-comments, and one unrelated call, `credmgr_mcp::server::run` in `crates/cli/src/main.rs`'s `cmd_mcp()` |
| Absence of any V1 reader in any crate | `built` | `grep -rni "migrat" v2/crates --include='*.rs'` → 0 matches; no V1 format module exists |
| Absence of a `migrate` CLI subcommand, and of any import that reads a V1 format | `built` | `crates/cli/src/main.rs::run` — 24 top-level arms, none of them `migrate`; the one `import` arm (`cmd_import`) parses `.env` text only (`crates/cli/src/dotenv.rs`) and has no relationship to V1 (§5) |
| `emergency-decrypt.mjs` — disaster recovery for a **V2** vault | `built` | `v2/scripts/emergency-decrypt.mjs`, exercised by `crates/cli/tests/emergency_decrypt.rs` |
| Manual carry of one value, V1 → V2 (§6) | `built` | The CLI plumbing is built and tested (`no_secret_in_argv.rs`), and the two rows above — the vault to write into, the running broker to write through — closed with `ADR-061`. No automated test pipes V1 into V2 and none can: that join needs a V1 install this workspace deliberately does not vendor |
| `credmgr import` for `.env` files (§5) | `partial` | built 2026-10-02: `crates/cli/src/main.rs::cmd_import` parses `.env` text (`crates/cli/src/dotenv.rs`) and writes it through `entry.create_batch` (`ADR-073`, single-value form), all-or-nothing, into a node named by `--node`; locked-vault batches are held for review. Not built: the preview with confirmation, and the skip / `--replace` collision options. Proven by `crates/cli/tests/cli_parity.rs` (`import_*`, `an_import_*`) |
| Short-name alias, and prefix-stripped display (§4) | `planned` | `grep -rni "alias" v2/crates` finds one unrelated comment in `store/src/paths.rs` and no alias support |
| V1 → V2 migration tooling, dry run, parallel window, cut-over | `removed` | `12_BUILD_PLAN.md` Phase 4: "There is no migration tooling." `ADR-028` and `ADR-034` are marked VOID in `14_DECISIONS.md` |
| A build phase for migration | `removed` | the autonomous build's path is `0 → 1 → 2 → 3 → 4 → 5 → 7 → 8` (Phase 6 is the external UI track, `19_FRONTEND_DELIVERY_SCOPE.md`); no phase in it is a migration, and the deleted one was not renumbered into hiding |

## 3. Why this document used to say something else

The first three passes designed an elaborate V1 → V2 migration: an allowlisted mapping of the
maintainer's credentials, per-value digest verification, a 14-day parallel window, a 45-day
read-only fallback, alias collision handling, a mandatory human-reviewed dry run, and a whole
build phase devoted to running it.

**All of it solved a problem nobody had.** No one ever asked for it. It was inferred, once, from
the fact that the author had a V1 vault — and then every later session treated the inference as a
requirement, because by then it was written down in four places. The count is not rhetorical:
`01_CONCEPT.md §7` records that retracting the assumption "updated four documents and a build
phase but missed this one", which is how a fifth contradiction survived until a later
verification pass caught it.

The cost was not confined to a wasted document:

- **A whole build phase** existed to run a migration that will never run.
- **Phase 4 carried migration tooling** — Node scripts to read V1's on-disk format — for the same
  non-existent operation. Phase 4 now says, in its own text, that there is none.
- **The build could not run unattended to the end**, because the invented phase required a human
  to review a report that would never be produced. The build's actual path is
  `0 → 1 → 2 → 3 → 4 → 5 → 7 → 8`, with no stop in it.
- **The supervisor grew a guard against the imaginary operation, and that guard endangered the
  real build.** `v2/scripts/autobuild.sh` halted if a V2 vault store appeared, on the theory that
  it signalled an unattended migration. Phase 5 and Phase 6 testing create a V2 vault
  legitimately, so the guard would have stopped the real build to prevent an imaginary one. It
  was removed, and the removal is recorded in place in the script rather than silently reverted.

The guard that **stayed** is the one that matters, and the contrast is the lesson: `autobuild.sh`
still fingerprints the live V1 vault before and after every session — by the checksum of its
decrypted contents, its sorted credential-name set, and its identity key, never by the ciphertext,
which changes on every save and would have fired within the hour. That guard protects something
real. The migration guard protected a hypothesis.

Recording this because the failure is instructive and cheap to repeat: a plausible-sounding
requirement, never stated by anyone, propagated into four documents, a build phase, two ADRs and a
piece of automation before anyone asked whether it was true.

<!-- figure:phantom-requirement-propagation -->

**Figure.** How far one unstated assumption travelled before anyone checked it: from the single
inferred requirement to the four documents, the build phase, the two ADRs and the automation
guard it reached — and the near-miss that guard would have caused. See §9 for the sources behind
every node.

### 3.1 What it changes across the corpus

| | |
|---|---|
| **Phases** | The autonomous build runs 0–5 then 7 (hardening and closeout), capped by 8 (final audit); Phase 6 is the external UI track. The migration phase is deleted, and deleting it is what renumbered the old hardening phase from 8 to 7 — the Phase 8 that exists now is a later, unrelated addition (`2026-08-08`), not the migration phase under a new number. |
| **Stops** | **None.** The autonomous build runs start to finish. The only human stop had been the migration review. |
| **Phase 4** | CLI only. No V1 migration or verification scripts. `emergency-decrypt.mjs` **stays** — it is disaster recovery for a V2 vault and has nothing to do with V1. |
| **V1 in this repo** | A working Node product, published as-is. Not a source to import from. |
| **The `v1/` and `v2/` relationship** | None at runtime. Two independent programs that share a name and a repository. |
| **`ADR-028`** (migrate flat) | **VOID** — nothing migrates. |
| **`ADR-034`** (V1 retired on evidence) | **VOID** — V1 is not being retired. It ships and is supported. |
| **`Q-1`** (split projects at migration) | **VOID** — the question presupposed the operation. |
| **`ADR-032`** (keep long names, show short) | **Still applies**, and §4 restates what it now means. |

### 3.2 Residue still in the repository, as of this rewrite

Retracting an assumption is not one edit, and as of this rewrite one file still describes the
deleted design as though it were the plan:

- **`v2/CHANGELOG.md`, section "Migration"**, still summarises the whole retracted design — "V1
  opened read-only, mandatory dry run, per-value digest verification, a 14-day parallel window,
  and a 45-day read-only fallback" — and points at this document as its source. That description
  is of the design deleted on 2026-08-05; nothing in it is true of the shipped product. It is named
  here rather than quietly fixed, because it belongs to a different owner and a silent edit is how
  the original inconsistency became invisible in the first place.

A second file used to belong on this list and no longer does: **`09_UI_UX_SPEC.md §12`** ended its
first-run sequence with "This is where V1 migration is offered" — a screen for an operation that
does not exist. That document's own rewrite, completed the same session as this one, found and
retracted the line; §12 now cites this document's §1 and §6 for the actual no-import, manual-carry
behaviour instead. Recorded here so a later pass does not re-flag it as still open.

A reader who finds the CHANGELOG.md residue should treat this document as the authority.

## 4. Names and aliases, without a migration — **`planned`**

`ADR-032` was written as a migration rule: keep V1's long credential names verbatim, register the
short form as an alias, and display the name with the node prefix stripped when it matches the
containing node. All three clauses survive the no-migration decision, because only their *cause*
was migration — they describe how names behave, and names behave that way regardless of where they
came from.

**What is timeless, and is built.** Entry names are unique per node, not per vault
(`03_DATA_MODEL.md §3`). That is the point of the node model: names stop being a global namespace,
so they stop needing `PROJECT_` prefixes to disambiguate. A vault may hold two entries called
`DB_PASSWORD` in two nodes and neither is ambiguous. The broker enforces this per node and cites
the same section where it does — the sealing path in `crates/brokerd/src/ops.rs` disambiguates
rather than drops when two sealed nodes' entries collide inside the orphan node.

**What is `planned`, and is not built.** No alias support exists in any crate today — a search
for `alias` across `v2/crates/` returns a single unrelated comment about directory naming. When it
is built, the target design is:

- **Storage will keep whatever name the user typed, verbatim.** `ACME_VPS_PASSWORD` will be stored
  as `ACME_VPS_PASSWORD`. Identity will never be rewritten on the user's behalf, because every
  consumer on the machine — shell helpers, deploy scripts, other agents — resolves by name.
- **A short form will be registered as an alias, not as a rename.** Inside a node named `acme`,
  both `credmgr get ACME_VPS_PASSWORD` and `credmgr get VPS_PASSWORD` will resolve to the same
  entry. The alias will be an additional key into the same entry id, never a second entry.
- **Display will strip the node prefix when it matches the containing node**, so the entry will
  read `VPS_PASSWORD` inside `acme`. Display and identity will be decoupled, which is what makes
  a rename optional forever rather than urgent.
- **Alias collisions will be refused, not resolved.** If stripping a prefix would produce a name
  another entry in the same node already holds, no alias will be registered and the long name will
  stand alone. The old design's collision-handling machinery existed to reconcile one specific
  imported vault; with no import, a collision can only arise from names a user chose in the same
  node, and the correct response to that is to say so rather than to guess.

**A correction for readers arriving from the data model — already fixed at the source.** An
earlier revision of `03_DATA_MODEL.md §3` described this rule as something "migration" does —
"Migration keeps the V1 names as-is and records the short name as an alias". That document's own
rewrite, completed the same session as this one, retracted the sentence and now quotes it only as
prior text being corrected: "**There is no migration, and this document no longer claims one.**
The previous text said…" The rule itself was never wrong; only its stated cause was. Nothing is
imported, so nothing is *kept*; the names are simply the ones the user typed, and the alias is a
convenience over them.

## 5. `credmgr import` — the only import V2 will ever have — **`partial`**

V2 imports nothing at install. Separately from that, a credential manager needs a way to absorb a
`.env` file, because that is where credentials arrive from in practice. `credmgr import` is that
feature, and it **exists** since 2026-10-02 (`crates/cli/src/main.rs::cmd_import`,
`crates/cli/src/dotenv.rs`; the 21 → 23 top-level subcommands are this and `notes`). It writes
through `entry.create_batch`, which takes 1–500 single-value entries for one named node, validates
every one before the first write, and holds a locked vault's whole batch in the pending tray
(`ADR-073`). `08_FIELD_MODEL.md §3` refers to it as the explicit `.env`-specific path that the bulk
parser deliberately does not try to be.

**Built** (`crates/cli/tests/cli_parity.rs`, `crates/cli/src/dotenv.rs` unit tests,
`crates/cli/tests/no_secret_in_argv.rs`):

- **It takes a file path or `-` for stdin, not a value.** `credmgr import ./service.env --node <id>`.
  A path is not a secret, so the command does not breach the argv rule that keeps every actual
  secret off the command line (`10_API_AND_MCP.md §2`). The file is read whole, capped at 4 MiB, and
  its values go straight into the request; nothing in the command prints one.
- **It requires an explicit `--node`.** There is no inference of a destination from the file's
  directory, its name, or the caller's working directory. Importing into the wrong node is a
  boundary violation that no later cleanup fully undoes, because the entry was encrypted to that
  node's key on arrival.
- **It parses `.env` semantics only** — `NAME=value` lines, an optional `export ` prefix, quoted
  values honoured (single quotes literal, double quotes with `\n \r \t \" \\`, either may span
  lines — a PEM block is the usual reason), comments and blank lines skipped. It does not attempt
  YAML, JSON, or auto-detection between formats. `08_FIELD_MODEL.md §3.5` states the reason
  directly: ambiguity is how a `.env` line with a `#` inside its value loses that value.
- **A quoted value that runs into a line that itself starts like `NAME=…` is refused**, naming both
  line numbers. That is the signature of a forgotten closing quote; every dotenv reader would
  silently swallow the lines in between. No error ever carries a line's content — a line that fails
  to parse may be exactly the secret the operator meant to import.
- **An empty value is not an entry.** `.env.example` files are full of `KEY=` placeholders; they are
  reported back by name, not imported.
- **It is all-or-nothing at the broker.** More than 500 entries is refused before anything is sent.
  A name already on the node, a duplicate, or a capability the caller lacks creates nothing at all,
  not even the valid half. A batch that stops part-way exits non-zero and says exactly how much was
  saved.
- **It works on a locked vault** the way `entry.create` does, queuing into the pending review tray
  (each name is reported `held`) rather than failing; `credmgr pending` reviews it after unlock.
- **It does not delete or rewrite the source file**, and says so: it prints a note that the file
  still holds the plaintext values.

**Not built** — the rest of the target design:

- **A preview with confirmation** listing each name, its destination node, and whether it collides,
  values masked. Today the command reports what it did after doing it.
- **Collisions default to skip, with `--replace` as an opt-in** routed through `entry.update`. Today
  a collision refuses the whole batch, which is the safe direction but not the designed one.

This is a product feature that happens to read a file format. It is not a migration, it has no
relationship to V1, and it is not a precedent for one.

## 6. Carrying one value across by hand — **`built`**

If a user wants a specific V1 credential inside V2, the path is one pipe, and both halves now
exist. V1's `credmgr get NAME` writes the value to stdout today, unchanged — V1 is a
shipping product and this repository does not touch it. V2's `credmgr set NAME --node <id>` reads
its value from stdin and never from argv, which
`crates/cli/tests/no_secret_in_argv.rs` asserts structurally; and since `ADR-061` there is both a
vault for that write to land in (`credmgr init`) and a shippable process serving the socket it
reaches over — `credmgrd`'s own `main()` calls `credmgr_brokerd::server::run` on
`<vault>/run/broker.sock` (§1), where until 2026-08-31 it printed one status line and exited and
every call site of that function was a test fixture. And since `ADR-063` (2026-09-24) the carried
value outlives the process: before that, a restarted daemon kept the ciphertext file and lost the
entry's name and node, and could not unlock the vault at all. That is what this section previously
described. What is still unproven is the join itself: no test pipes a real V1 binary into a real
V2 one, because the workspace does not vendor V1.

Three properties of that path, stated so nobody has to discover them by running it:

- **The value crosses in the clear, in process memory and a pipe.** That is the honest
  cost of a manual carry, and it is why this is designed as a per-credential decision rather than a
  loop over a whole vault. In the piped form it reaches no file and no shell history, because
  neither side takes the value as an argument — but a user who redirects the first command into a
  file will have written a plaintext credential to disk, and nothing in either program will be able
  to undo that.
- **On a locked V2 vault the write is queued, not lost.** This part already runs, proven
  against the broker directly (not over the socket, and not through a shipped binary):
  `entry.create` accepts writes while locked and lands them in the pending review tray for
  confirmation at the next unlock
  (`isolation.rs::i18_create_while_locked_lands_in_pending_and_update_is_refused_until_accepted`).
- **Nothing about V1 changes.** The read is a read. V1 keeps the credential, keeps its refs,
  and keeps working; there is no shim, no dual-write, and no clock counting down to an archive.

## 7. The bar for ever revisiting this — **not on the roadmap**

This section exists so that a future session proposing a migration tool has to clear a stated bar
rather than re-derive the original assumption from scratch.

A V1 → V2 import tool would be a **post-1.0 feature request**, designed then, against a real
requirement. It would not be reopened by any of the following, each of which was the actual basis
of the original design: the author owning a V1 vault; the two products sharing a repository; a
migration being technically straightforward; or a document somewhere still implying one exists.

It would be reconsidered only on all four of:

1. **A stated request from someone who is not the author**, describing a vault they want moved and
   why moving it by hand is insufficient.
2. **A V1 read path that is provably read-only** — a wrapper that cannot write, tested by
   attempting a write and asserting the failure, not by convention.
3. **A dry run that is the default and cannot be skipped**, whose report names every entry, its
   destination node, and its collision disposition before anything is written.
4. **A destination that is stated, never inferred.** Every entry's target node explicit, because
   the encryption follows the node and an entry imported into the wrong one was encrypted to the
   wrong key.

Until then this document's design content is complete, and it is complete in the negative: **there
is no target design for a migration subsystem here, because the finished state of migration in
this product is that it does not exist.** Writing out a full specification for a subsystem that is
decided against is how the original mistake was made the first time.

## 8. Connections

| Direction | Document | What flows across |
|---|---|---|
| feeds | `03_DATA_MODEL.md §3` | the per-node name uniqueness and alias rule §4 restates without a migration; `03_DATA_MODEL.md`'s own Connections table cites this document whole, not by section (`decided by | 11_MIGRATION.md | …`), not §4 specifically |
| depends on | `08_FIELD_MODEL.md §3` | the bulk grammar that deliberately excludes `.env` semantics, which is why §5's `credmgr import` is a separate path (built, `partial`) |
| depends on | `10_API_AND_MCP.md §2` | the CLI rule that a secret value never appears in argv, which §5 and §6 both inherit |
| depends on | `14_DECISIONS.md` | `ADR-028` and `ADR-034` (both VOID here), `ADR-032` (survives as §4's naming rule), `ADR-059` (the status vocabulary §2 uses) |
| feeds | `06_ACCESS_GRAPH.md §8` | the fact that a hand-built vault, not an imported one, is what an operator's first deliberate node pair is created in |
| feeds | `18_ENDPOINT_INDEX.md §2` | the absence of `migrate` from the CLI surface that index enumerates as removed; `import` is listed there as carried forward from V1, not absent — its `partial` status here is this document's own claim in §5, not one §2 makes |

## 9. Source

**Design.** `ADR-028` (VOID), `ADR-032` (naming and alias display), `ADR-034` (VOID), `Q-1` (VOID)
— all in `14_DECISIONS.md`. `ADR-059` supplies the `built`/`partial`/`planned` vocabulary; the
`removed` row in §2 is borrowed from `18_ENDPOINT_INDEX.md`'s legend for the same reason it exists
there.

**Code.** `crates/cli/src/main.rs::run` — the 24 top-level subcommand arms, which is the
authority for "no `migrate`" (and for the one `import`, which reads `.env` text only). `crates/store/src/paths.rs` — `default_vault_dir()` and
the `CREDMGR_VAULT_DIR` override, the authority for where an empty V2 vault appears.
`v2/scripts/emergency-decrypt.mjs` — V2 disaster recovery, retained. `v2/scripts/autobuild.sh` —
the live-vault fingerprint that stayed and the in-place comment recording the migration guard that
was removed.

**Tests.** `crates/cli/tests/no_secret_in_argv.rs` (§6's argv property);
`crates/cli/tests/emergency_decrypt.rs` (§2's recovery row);
`crates/store/src/paths.rs::vault_and_state_dirs_never_coincide` (§1's vault location);
`crates/brokerd/tests/vault_init.rs` and `crates/cli/tests/vault_init.rs` (§1's and §2's bootstrap
rows, `ADR-061`).
`cargo test --workspace -- --list`: 813 tests in 50 test binaries (2026-10-03); the last full run recorded:
571 passing, 0 failing, 41 test binaries (2026-10-02); it read 448
passing across 37 test binaries on 2026-09-24 (re-measured 2026-10-01) and 406 passing across 35
test binaries when verified 2026-09-13 (run `34743281942`). That line read 397 passing across 33 test binaries when verified 2026-08-18; that
figure is recorded rather than overwritten because it was true on its date, and the two added
binaries are the `vault_init.rs` pair above. 2026-09-24 added a 36th and a 37th binary,
`crates/brokerd/tests/durable_vault.rs` (§2's `credmgrd` row) and
`crates/mcp/tests/schemas_match_the_broker.rs` (the MCP tool schemas checked against the broker's
real ops); see `BUILD_LOG.md`'s latest entry for the current count.

**Verification.** The negative claims are greps, and they are the point of this document, so they
are written out to be re-run: `grep -rni "migrat" v2/crates --include='*.rs'` → 0 matches;
`grep -rni "alias" v2/crates --include='*.rs'` → one unrelated comment in `store/src/paths.rs`
(a test comment about `archive_dir`'s flat namespace never "aliasing" two different archive
kinds). The 24 top-level subcommand arms
need the match block scoped, not a blind grep over the whole file — and scoped by function, not by
line range, because the line numbers keep moving: `awk '/^fn run\(/,/^}/'
v2/crates/cli/src/main.rs | grep -cE '^\s+"[a-z]+" =>'` → 24 (re-run 2026-10-03; 23 on 2026-10-02, before `field`). The unscoped
`grep -nE '^\s+"[a-z]+" =>' v2/crates/cli/src/main.rs` returns 40 (39 before `field`) — it also matches the nested
`gate`/`node`/`grant` sub-command arms (`"verify"`/`"enroll"`/`"recover"` inside `cmd_gate` —
`cmd_doctor` has no string-matched subcommand, only boolean flags — and
`"create"`/`"workdir"`/`"ls"`/`"seal"`/`"restore"`/`"ls"`/`"revoke"` inside `cmd_node`/`cmd_grant`)
— that is not the recipe for this claim, and re-running it unscoped will report the wrong number.
It returned 27 before 2026-09-24 added `gate enroll`, `gate recover` and `node workdir`. Both
counts moved by one, and every line number in this recipe moved, when `ADR-061` inserted `"init"`
at line 45: the scoped count was 19 over `45,63p` and the unscoped 26, with `cmd_gate`'s
`"verify"` at line 249, in the 2026-08-19 revision of this document.
`python3 -m tools.corpus_check crossrefs` is not scoped to `## Connections` tables at all: it
strips fenced code from every `*.md` file directly under `v2/docs/` and regex-matches
`NN_NAME.md §S` anywhere in the remaining prose, so it does check whether another document's text
still cites a section here — but only that the cited section *number* exists in the target, never
that the citation is about the right thing (the wrong-section-citation class this backlog exists
to catch is invisible to it either way). It also never reaches `v2/CHANGELOG.md` — §3.2's
residue — because that file sits outside `v2/docs/`, the one directory the tool globs; that is a
directory-scope gap, not a table-versus-prose one. Separately, and correctly: `03_DATA_MODEL.md`
in fact carries no live reference to this document's §4 (see §4).

**Figure.** `phantom-requirement-propagation` (§3) — built, `docgen` `kind: "flowchart"`, spec at
`v2/docs/11_MIGRATION_spec.json` per `ADR-060`. Ten nodes, each citable to a real file: the
inferred requirement itself; the four documents that carried it (`11_MIGRATION.md`'s own first
three passes, `03_DATA_MODEL.md §3`, `09_UI_UX_SPEC.md §12`, and `v2/CHANGELOG.md`'s "Migration"
section — the one node still not fixed, per §3.2); the deleted migration build phase
(`12_BUILD_PLAN.md §2.5`); the two voided ADRs (`ADR-028`, `ADR-034` in `14_DECISIONS.md`); the
removed `autobuild.sh` guard (`v2/scripts/autobuild.sh:261-264`); and the near-miss that guard
would have caused, dashed because it never fired. Rendered from spec: `grep -c '<figure'
v2/docs/11_MIGRATION.html` and `grep -c '&lt;svg' v2/docs/11_MIGRATION.html` verified after every
build.
