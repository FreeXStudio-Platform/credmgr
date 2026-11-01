---
id: V2-008
classification: public
title: Field model and bulk parser
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-18
---

<!-- artifact-hardened: NEEDS RE-HARDENING — rewritten this pass, 2026-08-18, following the
     same corpus contract `17_AIRLOCK_AND_LLM.md` was corrected under (ADR-058/059/060). The
     previous stamp (`Approved With Known Risks @ 6ee1e5f`) attested to a Pass-1 document with no
     front matter, no built/planned distinction anywhere, and no `## Connections`/`## Source`
     sections — every claim in it was written as though built. The single largest gap: §2, §4,
     §5 and §7 described a multi-field bulk-paste product (an "Add field" control, a live
     preview, per-field editing) as the *only* field UI, with no marker that none of it is wired.
     It is not. `crates/core/src/parser.rs` (the bulk grammar) and `crates/core/src/inference.rs`
     (type/sensitivity/masking inference) are real, tested, and correctly described by the old
     §3/§6 in substance — but `crates/core::parser::parse_bulk` has no caller anywhere outside its
     own test suite, and `entry.create`/`entry.update`/`entry.rotate` (`crates/brokerd/src/
     ops.rs`) each accept exactly one `value` and one optional `label`. `field_count` is the
     literal `1` at both real construction sites (`ops.rs:1262`, `:1280`) and is never touched
     again by any other op. A field's `label` is read once, fed to `infer_field_type`, and then
     discarded — it is not a column of `ManifestEntry` and is not stored anywhere. This pass marks
     every one of those gaps explicitly, keeps every real design detail as the target ("planned"),
     and corrects one inference claim (the `wallet`/"address-shaped field" qualifier) that
     `03_DATA_MODEL.md §5` had already found and fixed independently. Not source-of-truth until an
     operator re-hardens it.

     Round-2 verification pass, 2026-08-19: two findings from
     `VERIFICATION_BACKLOG_S21_ROUND2.md` fixed after re-deriving both from live source. (1) §5
     claimed "`09_UI_UX_SPEC.md` has no screen for [a preview]" — false: `09 §7` does design a
     screen with a Step-3 PREVIEW box; the accurate distinction is that 09's preview is a thin,
     itself-`planned` one-line summary that defers to this document's own §5 for field-level
     detail, not that no screen exists at all. (2) §3.4 and §8 mischaracterised `P-1`
     (`p1_seal_open_round_trips`) as testing "0 B–4 MiB" of arbitrary bytes; the live strategy is
     `prop::collection::vec(any::<u8>(), 0..4096)` — 0 to ~4 KiB, roughly 1000x smaller — and §8's
     table separately misattributed the real 1 MiB case to `P-1` when it is
     `envelope.rs::round_trip_empty_and_large`, a plain unit test outside the proptest. Both fixes
     replace the wrong claim with the ultimate-destination-correct one; neither finding required
     touching any other section. Still not source-of-truth until an operator re-hardens it.
     Updated 2026-09-24 for ADR-073 (`entry.create_batch` dispatched in its single-value form —
     §3.5, §4 and the status line; the multi-field form stays `planned`).

     Rewritten 2026-10-03 for ADR-078 — the field model is BUILT. Everything this note and the status line
     below recorded as unwired is wired: the broker stores a field document (ids, free-text labels,
     per-field type and masking overrides) sealed as envelope version 2, the four `field.*` operations and
     `entry.get` exist, `parse_bulk_segments` has callers (the CLI's `set --bulk`, the desktop shell's
     `fields_preview`), the preview is shown before anything is saved, and §8's row 7 is gated by
     `crates/core/tests/no_field_schema.rs`. The `parser-built-broker-unwired` figure was redrawn as
     parse → preview → seal. Still not source-of-truth until an operator re-hardens it. -->

# The field model and the bulk parser

`CredMgr V2` · entry fields, sensitivity, and type inference · `2026-08-18`

> **Status.** The **field model is built** (`ADR-078`). The bulk-paste parser (§3) and the
> type/sensitivity/masking inference (§6) are real functions with real property tests, and everything
> downstream of them is wired: a client parses a paste (the CLI's `credmgr set --bulk`, the desktop
> shell's local `fields_preview`), shows the preview, and sends the previewed `fields` to `entry.create`
> (or one item per `///` segment to `entry.create_batch`); the broker validates them, seals them as one
> field document in an envelope of version 2 and projects the entry's type, sensitivity, field count and
> `hasTotp` into the manifest; `entry.get` lists the fields (labels, types, masking — never a value);
> `field.add`, `field.update`, `field.remove` and `field.reorder` edit them one at a time, each undoable;
> a label is **stored** (it used to be thrown away). What is *not* built: the design's richer entry-type
> tree (`login`, `api`, `ssh` — core's `wallet`-from-a-lone-key rule differs, §6.2), a "looks sensitive"
> hint on a typed-`text` field (§5), and a label or value *search* (the broker's `search` matches entry
> names only). Entries written by `2.0.0-alpha.6` are read in place as one field (§7).

---

## 1. What is deleted

V1's `TYPE_SCHEMAS` prescribed field names per category — a wallet "has"
`chain, walletType, address, publicKey, privateKey, seedPhrase, derivationPath,
accountIndex, xpub, zpub, purpose`; an API service "has" `apiKey, apiSecret, token,
clientId, url, accountId`. The dashboard rendered these as add-column chips, and
`missingSchemaFields()` nagged about the ones you had not filled in.

**All of it is deleted** (`ADR-011`). Schemas, the chips, the "incomplete" nagging,
`schemaForCategory`, `missingSchemaFields`, `orderFieldsBySchema`, `fieldLabelForName`. None of
this exists anywhere in `v2/crates/` — there is no field-name vocabulary to delete a second time.

The reason is not simplicity for its own sake. A schema is a *prediction* about what a secret
looks like, and it is wrong often enough that the user ends up fighting it: renaming a field
to fit, or leaving the prescribed one blank so the entry reads as incomplete forever. The
user knows what they pasted. The system's job is to keep it, label it as they said, and never
lose a byte.

**What replaces it:** one button, two modes, free-text labels that are stored, inferred types that are
always overridable (a pin is kept only when the user makes one). `crates/core/tests/no_field_schema.rs`
is the gate that keeps the deletion true: it greps `crates/` and `apps/desktop/src*` for the old names and
fails on any.

---

## 2. The add-field control

**`built`.** There are two places a field is added, and they share one rule: *the label is whatever the
user typed*. No dropdown, no autocomplete list, no validation against a vocabulary; an empty label is
allowed and is shown as `field N`.

**Add entry** (`+ New entry` / `+ New note` in the inspector, or the `N` key) is a dialog with two modes:

```
┌──────────────────────────────────────────────────────────────────────┐
│  where [node ▾]   name [          ]                                  │
│  ● Single   ○ Bulk                                                   │
│  ┌ label ────────┐ ┌ value (grows, multi-line) ───────────────┐ [✕]  │
│  └───────────────┘ └───────────────────────────────────────────┘     │
│  [ + Add field ]          ← more rows; each is one field             │
│  ┌ preview — what will be stored; nothing is written until you save ┐│
│  │ host      db.example.com                    [host ▾]             ││
│  │ password  ••••••••••••                      [password ▾]         ││
│  └───────────────────────────────────────────────────────────────────┘│
│  3 fields · 2 masked  entry type [auto ▾]  highest sensitivity: high │
│                      [ Cancel ]  [ Save and add another ]  [ Save ]  │
└──────────────────────────────────────────────────────────────────────┘
```

**Single** is a list of label/value rows (`+ Add field` appends one). **Bulk** is one large textarea: the
user pastes a whole block, and the grammar (§3) turns it into fields. A paste that is one unlabelled blob of
three or more lines gets a one-click **"Make each line its own field"** offer (§5). Both modes feed the same
preview, and the preview feeds the same save. `+ New note` opens the form with one field labelled `note` and the
entry type pinned to `note` (§6.2). There is no third mode and no per-type form.

**The entry detail's `+ Add field`** adds one field to an existing entry (`field.add`, §7). Each field row's
`⋮` menu offers *Edit…* (label, value, type, masking — `field.update`), *Move up* / *Move down*
(`field.reorder`) and *Remove…* (`field.remove`; refused for the last field).

**On the wire.** A client sends `fields: [{label, value, type?, masked?}]` to `entry.create` — or the old
`{value, label?}` form, which means exactly `fields: [{label: label ?? "value", value}]`. The CLI's
`credmgr set <name> --bulk` reads the paste from stdin, parses it with `credmgr_core::parser` (the same code
the desktop preview runs) and sends the structure; `credmgr set <name>` with no flag still creates a
one-field entry labelled `value`. **The broker never parses the grammar** (ADR-078 D5) — the preview is
computed where the user is typing, and what was previewed is sent verbatim.

## 3. The bulk grammar

**`built`.** `crates/core/src/parser.rs` implements exactly this grammar — total, deterministic,
lossless, order-preserving, duplicate-tolerant (§3.4) — and is proven so by the property suite
(`crates/core/tests/properties.rs`: P-6, P-7, P-8) plus its own unit tests, one per row of §3.2's
table and one per §3.3's worked example. **What is built is the pure function
`credmgr_core::parser::parse_bulk(&str) -> Vec<ParsedField>` and its segment-preserving form
`parse_bulk_segments(&str) -> Vec<Vec<ParsedField>>` (one inner vector per `///` block), with
`parse_bulk` defined as its flattening — property P-18 pins the equivalence over 10,000 cases.** Its
callers are the clients: `parse_bulk` from `credmgr set --bulk` and `credmgr field add --bulk` in the CLI
(`crates/cli/src/fields.rs`), and `parse_bulk_segments` from the desktop shell's local `fields_preview`
(`apps/desktop/src-tauri/src/fields_preview.rs`). No caller in `crates/brokerd`
or `crates/mcp` invokes it, by design (§4). Two rules, and they fit in one sentence each.

> **Rule 1 — a field per line.** A line of the form `label: value` (colon, then a space)
> becomes one field.
> **Rule 2 — `///` separates.** A line containing only `///` ends the current field and
> starts the next, so a value can span many lines.

### 3.1 Normative grammar

```
document   ::= segment ( SEP segment )*
SEP        ::= LINE_START WS* "///" WS* LINE_END
segment    ::= line+

; a segment is resolved by exactly one of these two cases, in order:

CASE A — "every non-empty line is labelled"
   if every non-empty line in the segment matches LABELLED_LINE
      → each such line produces one Field { label, value }

CASE B — otherwise, the segment produces exactly ONE Field:
   if the segment's first line matches LABEL_ONLY
      → label  = that label
        value  = the remaining lines, verbatim, with the trailing newline trimmed
   else
      → label  = ""            (rendered as "field N", user-editable)
        value  = the whole segment, verbatim

LABELLED_LINE ::= LABEL ":" " " WS* VALUE_TEXT
LABEL_ONLY    ::= LABEL ":" WS* LINE_END
LABEL         ::= 1..40 chars matching [A-Za-z0-9 _.()#/-]+
                  AND not one of the reserved URI schemes:
                  http https ftp ftps ssh sftp git file postgres postgresql
                  mysql redis mongodb amqp otpauth data mailto s3 gs
```

**`LABELLED_LINE`'s trailing `WS*` does not mean what it appears to mean, and this is decided,
not an oversight (`ADR-038`).** Read literally, `" " WS*` would strip leading whitespace from the
value — `"password:  x"` (two spaces) would store `"x"`. §3.5 states the opposite guarantee
plainly: no trimming beyond the trailing newline. `ADR-038` resolves the contradiction in favour
of the prose: **exactly one literal space is the separator; everything after it, including
further leading whitespace, is the value, untouched.** The grammar's `WS*` is imprecise shorthand
for "there is a space here," kept in this normative form because it is definitional scaffolding,
not because it is the rule that shipped. `parser.rs::tests::leading_and_trailing_spaces_in_value_survive`
is the test that holds the shipped behaviour, and `parser.rs`'s own module doc records the same
resolution independently of this document.

### 3.2 Why "colon **space**" and not just "colon"

Because values are full of colons (`ADR-014`):

| Input line | Parsed as | Why |
|---|---|---|
| `host: db.example.com` | field `host` = `db.example.com` | colon + space |
| `db.example.com:5432` | unlabelled field = the whole line | no space after colon |
| `https://api.example.com` | unlabelled field = the whole line | scheme is reserved, and no space |
| `url: https://api.example.com` | field `url` = `https://api.example.com` | the *first* colon+space wins |
| `note: ratio is 3:1` | field `note` = `ratio is 3:1` | only the first colon+space splits |
| `private key:` + following lines | field `private key` = the following lines | `LABEL_ONLY` |

Every row above is a named unit test in `parser.rs`'s `#[cfg(test)] mod tests`. The rule the
user has to remember is **"label, colon, space, value"** — which is what people already type.

### 3.3 Worked examples

**(a) A server block — Case A, four fields, no `///` needed.** Matches
`parser.rs::tests::worked_example_a_server_block` exactly; `203.0.113.4` is an RFC 5737
documentation address, not a real host.
```
host: 203.0.113.4
port: 22
username: root
password: hunter2-not-really
```
→ `host` · `port` · `username` · `password`

**(b) A key that spans lines — `///` earns its keep.** Matches
`parser.rs::tests::worked_example_b_key_spanning_lines`.

Not a real key below — the body is a placeholder, deliberately not base64, and the header's
algorithm word is `«ALGORITHM»` rather than a real one (a real paste would name its actual
format there instead of the placeholder), so nothing here can be mistaken for (or
pattern-matched as) real key material. The point being illustrated is structural: everything
between the `///` markers, byte for byte and newline for newline, becomes the value of one
field.
```
username: deploy
///
private key:
-----BEGIN «ALGORITHM» PRIVATE KEY-----
⋮ the rest of the key, byte for byte, exactly as pasted ⋮
-----END «ALGORITHM» PRIVATE KEY-----
///
passphrase: correct horse battery staple
```
→ 3 fields; the key keeps every byte and every newline.

**(c) An agent pastes an unstructured blob — the tolerated case.** Illustrative of
`parser.rs::tests::worked_example_c_unstructured_blob`, with the address in that fixture
replaced here by a hostname rather than an RFC 1918 literal, per this corpus's own "never a
private-range IP" rule (§4.4 of `00_README_START_HERE.md`):
```
prod db is at db-01.example.com port 5432 user svc_app pw Z9!kq2 rotate quarterly
```
→ **one** unlabelled field containing the whole string, type `text`, unmasked-by-default. Nothing is
dropped, nothing is guessed into structure. The preview shows it as one field and offers *"Make each line
its own field"* (§5). **A "looks like it contains a secret" hint is `planned`** — no part of the preview
computes it.

This is the brief's *"a system might write the entire set of data back-to-back"* case. It is
**accepted and lossless at the parser layer**, but it is not documented as the way to do it.
Rules 1 and 2 are the documented contract. The MCP tool descriptions deliberately do **not** teach the
grammar: an agent sends structure (`fields: [...]`), because the broker does not parse text
(`crates/mcp/src/tools.rs`, ADR-078 D11).

### 3.4 Guarantees the parser holds, and the evidence for each

1. **Lossless (for Case A input).** `P-6` (`p6_case_a_round_trips`,
   `crates/core/tests/properties.rs`, 10,000 generated cases) proves that formatting a set of
   `(label, value)` pairs as one `label: value` line each and parsing the result back recovers
   exactly those pairs. `parser.rs`'s own module doc records why this is proven against the
   documented canonical form rather than arbitrary byte soup: "reassembly === input" presupposes
   a reassembly function the grammar does not define for freeform text. A companion generated
   test, `label_only_multiline_value_round_trips` (10,000 cases), covers the `LABEL_ONLY`
   multi-line case and its one documented lossy edge — a value's trailing empty line is trimmed.
2. **Deterministic.** `P-8` (`p8_parse_is_deterministic`, 10,000 cases): same input, same output,
   always.
3. **Total.** `P-7` (`p7_parse_is_total`, 10,000 cases): every possible input parses without
   panicking. There is no rejection path, no error state, no "could not parse." Worst case is one
   unlabelled field. `parser.rs::tests::never_panics_on_pathological_input` additionally exercises
   NUL bytes, 1,000 repeated 4-byte emoji, a 50-char label, and bare `":"`/`"///"` inputs directly.
4. **Order-preserving and duplicate-tolerant.** `parser.rs::tests::duplicate_labels_both_preserved_in_order`:
   two fields may share a label; nothing is merged, deduplicated or renamed.
5. **Encoding-safe.** `parser.rs::tests::crlf_and_lone_cr_both_split_lines`: `\n`, `\r\n`, and a
   lone `\r` all split lines correctly. Values are stored as bytes; only the *display* — which
   does not exist yet — will normalise line endings.

**The pipeline is proven end to end up to display and copy.** `P-17`
(`p17_parse_seal_open_preserves_every_field`, 1,000 cases, `crates/core/tests/field_doc.rs`, with a
PEM-shaped strategy) runs `parse_bulk_segments` → build a field document → `seal_as(FieldDocument)` →
`open_any` → `decode` and asserts every label and value is byte-identical to the parser's output. The
envelope alone is proven by P-1 (`p1_seal_open_round_trips`, arbitrary bytes 0–4 KiB, 1,000 cases) plus a
dedicated 1 MiB unit test (`envelope.rs::round_trip_empty_and_large`); the document alone by P-13
(`p13_field_doc_round_trips`, 1,000 cases) and P-14 (`p14_decode_is_total`, 10,000 cases of arbitrary bytes,
plus P-14b, 1,000 mutated valid documents). What no automated test spans is the *display* and the *copy*:
those are the desktop's, and `RELEASE_VERIFICATION.md` records them.

### 3.5 Deliberate non-features

- No YAML/JSON/`.env` auto-detection. Ambiguity is how a `.env` line with a `#` in the value
  loses its value. If the user wants `.env` semantics they will use `credmgr import`
  (`10_API_AND_MCP.md §2.3`, `11_MIGRATION.md §5`), a separate, explicit, `.env`-specific path.
  The op it calls, `entry.create_batch`, is **`built`** (`ADR-073`, multi-field items since `ADR-078`,
  `10_API_AND_MCP.md §4.1b`), and the `credmgr import` command that reads a
  `.env` file into it is built too (2026-10-02, `11_MIGRATION.md §5` — without the preview).
- No trimming of value whitespace beyond the trailing newline (`ADR-038`, §3.1). A password may
  begin or end with a space, and truncating it silently is the worst possible bug in this
  product.
- No maximum field count and no maximum value length below the document limit (16 MiB per entry, 64 MiB
  per `entry.create_batch` call — `ADR-078`, enforced); a label is at most 200 characters, one line.

<!-- figure:paste-to-sealed-document -->

---

## 4. One entry or many?

**`built`** (`ADR-013`, `ADR-073`, `ADR-078`). A bulk paste creates **one entry with many fields** by default
— the common case is pasting one server's or one service's whole block — through a single `entry.create` whose
`fields` are the previewed ones. The preview offers one toggle: **"split each `///` segment into its own
entry."** When on, each segment becomes a separate entry, named from its first label (or `untitled 1…n`; the
screen makes the name unique among the node's existing names), and the client sends them as the items of one
`entry.create_batch` call — 1–500 entries, every item validated and encoded before the first is written, each
document at most 16 MiB and the call at most 64 MiB, a locked vault holding the whole batch in the pending tray,
a part-way failure answering `complete: false` with what was created (`10_API_AND_MCP.md §4.1b`). This resolves
the brief's ambiguity — *"separated by `///` to indicate that the credentials are separate"* — by supporting both
readings and letting the user see which one they are getting before saving. `ADR-013` records the decision and
the reason: the brief did not resolve the ambiguity itself, so the product does not force a reading on the user's
behalf.

---

## 5. The preview is the contract

**`built`** (`ADR-078` D5). The desktop's Add entry dialog shows, before anything is saved, exactly what will be
stored, and **no broker op returns a dry-run result**: the preview is the shell's own command,
`fields_preview {text?, fields?, split?}`, which runs `credmgr_core::parser`, `fields` and `inference` locally —
no socket, no session, no audit record, never logging its input (a broker preview would write an audit line per
keystroke and carry the secrets over the socket for nothing). It answers, for each entry-to-be,
`{suggestedName, fields: [{label, value, type, masked, inferredType, typeOverridden, maskedOverridden}],
entryType, sensitivity, fieldCount, hasTotp}`, plus `singleBlobHint`. The page keeps **no parser and no
inference of its own** (the design's JavaScript `parseBulk` / `inferType` disagreed with core in three places and
were retired): what the screen shows is core's answer, and what is saved is that answer, sent verbatim — a field's
`type` / `masked` are sent only where the user pinned them, and the entry's `entryType` only where they picked one.

```
  ┌──────────────────────────────────────────────────────────────────┐
  │  host        db.example.com                       [host]      ▾  │
  │  port        22                                   [port]      ▾  │
  │  username    deploy                                [username]  ▾ │
  │  password    ••••••••••••                         [password]  ▾  │  ← masked
  │  private key -----BEGIN «ALGORITHM» PRIVATE KEY----- …[private-key]▾│ ← masked, 3 lines
  └──────────────────────────────────────────────────────────────────┘
     5 fields · 2 masked · entry type: [auto ▾] · highest sensitivity: critical
```

- The `[type]` picker shows the **inferred** type (§6); choosing another pins it. Inference never decides.
- Masking follows the type (`default_masked`, §6); a masked value shows as dots in the preview.
- If the parse produced one big unlabelled field and the input had ≥ 3 lines, the dialog says so and offers
  **"Make each line its own field"** in one click — the recovery path for a paste that did not follow the rules.
  (`singleBlobHint`.)
- **Not built:** a small "looks sensitive" hint on a value typed `text` that resembles a secret — a nudge, not a
  block; nothing computes it.
- A mistaken `entry.create` that lands anyway is recovered with `entry.remove` (a real, 7-day soft-delete —
  `crates/store/src/entry_archive.rs`, `ADR-048`) followed by `entry.undo`, or by editing its fields.

The CLI previews nothing (it has no screen): `credmgr set --bulk` parses the stdin paste and sends it, and
`credmgr field ls` lists what was stored.

---

## 6. Type inference

**`built`.** `crates/core/src/inference.rs` implements both axes in full and is proven never to
mutate the value it classifies (`P-11`, `p11_inference_never_mutates_value`, 1,000 cases). Since
`ADR-078` the answer is **computed from the stored document, not cached in it**: `fields::project` runs
`infer_field_type` over each field's label and value (unless the user pinned a type), takes the strongest
`default_sensitivity` (unless pinned) and infers the entry type (unless pinned), and that projection is what
lands in the manifest. Every write re-projects. The surfaces a person uses to see or override the chip are the
preview's pickers (§5) and the field menu's *Edit…* (§7).

### 6.1 The eleven field types, and the exact order they are tried in

`infer_field_type(label, value)` tests the **value's shape first, the label second** — a URL
pasted into a field labelled `password` is typed `url`, not `password`; there is a test named for
exactly that case (`url_in_password_labelled_field_is_still_url`). The checks run in the exact
order below and stop at the first match — this order **is** the specification, since a single
value can satisfy more than one rule and the function is a `match` with no fallthrough:

| # | `FieldType` | Detected from | Masked by default | Sensitivity |
|---|---|---|---|---|
| 1 | `private-key` | value contains `-----BEGIN` **and** `PRIVATE KEY-----` | ✅ | `critical` |
| 2 | `certificate` | value contains `-----BEGIN CERTIFICATE-----` | ✕ | `high` |
| 3 | `totp-seed` | value starts `otpauth://`, **or** is 16/26/32 chars of base32 alphabet (`A`–`Z`, `2`–`7`) after trimming | ✅ | `high` |
| 4 | `seed-phrase` | value splits into 12/15/18/21/24 whitespace-separated words, all lowercase ASCII | ✅ | `critical` |
| 5 | `api-key` | value starts `sk-`, `ghp_`, `github_pat_`, `AKIA`, `AIza`, or `xox` + one of `a`/`b`/`p`/`r`/`s` + `-` | ✅ | `high` |
| 6 | `url` | value starts `http://` or `https://` | ✕ | `medium` |
| 7 | `port` | value parses as an integer 1–65535 | ✕ | `medium` |
| 8 | `host` | value is IPv4-shaped, or contains no space/`://`, contains a `.`, and every char is alphanumeric/`.`/`-` | ✕ | `medium` |
| 9 | `username` | value is email-shaped (`local@domain`, domain has a `.`, no spaces), **or** label contains `user` | ✕ | `medium` |
| 10 | `password` | label contains `pass`, `pwd`, or `secret` | ✅ | `high` |
| 11 | `api-key` (fallback) | label contains `key`, `token`, or `api` | ✅ | `high` |
| — | `text` | none of the above matched | ✕ | `low` |

`default_masked` and `default_sensitivity` (both in `crates/core/src/inference.rs` since `ADR-078`, which moved
`Sensitivity` and `default_sensitivity` out of the broker and the store so that the projection is pure core) are each an exhaustive match over all eleven
`FieldType` variants — the table's "Masked" and "Sensitivity" columns are not examples, they are
the complete function. Note `certificate`: `high` sensitivity but **not** masked by default — a
certificate is routinely public material, unlike a private key of the same nominal sensitivity.

### 6.2 Entry type: twelve variants, six an inference path can reach

`EntryType` (`crates/core/src/inference.rs`) has **twelve** variants: `server` · `database` ·
`api` · `wallet` · `login` · `ssh` · `certificate` · `token` · `totp` · `env-bundle` ·
`note` · `other`. (`note` was spelled `note-only` until `ADR-078`; it is the same variant, no vault ever held the
old spelling, and `note-only` is still accepted on input.) `infer_entry_type_labelled(&[(label, type)])` can
return **six** of them — `note`, `totp`, `wallet`, `certificate`, `server`, `other` — by this decision tree,
first match wins, and nothing selects the other six: they exist for the manual override (§5's entry-type
picker, `entryType` on the wire):

0. Exactly one field, its label `note` or `notes` (ASCII case-insensitive, trimmed) → `note`
1. Else any field is `totp-seed` **and there are at most two fields** → `totp` (a server that merely
   carries a 2FA seed stays a `server`; the manifest's `hasTotp` flag, not its type, puts it in `counts.totp`)
2. Else any field is `seed-phrase` or `private-key` → `wallet`
3. Else any field is `certificate` → `certificate`
4. Else the set contains `host` **and** `username` **and** (`password` **or** `api-key`) → `server`
5. Else → `other`

Rule 0 is the one place a label is read at all, and it is a suggestion for the entry type — the label stays
free text, and a field labelled `note` is not required to hold anything in particular. `infer_entry_type(&[types])`
is the same function with every label empty. `database`, `api`, `login`, `ssh`, `token` and `env-bundle` are
real, serialisable members with no inference path that produces them. The design's own JavaScript tree
(`login`, `api`, `ssh`; a lone PEM → `ssh`) is **not** adopted — the preview shows core's answer — and adopting
any of its rules is a product call for after beta.1.

**One inference is deliberately weaker than the spec, and the code says so.** An earlier version
of this document derived `wallet` from "a seed-phrase or private-key field **plus an
address-shaped field**." No `address` `FieldType` exists in §6.1's table, so there was nothing to
test that qualifier against; `03_DATA_MODEL.md §5` found and corrected this claim independently
of this rewrite. The implementation infers `wallet` from the key or phrase alone
(`inference.rs`'s own module doc records the same simplification, in the same words, as a
deliberate choice: under-inferring costs one click, inventing an address heuristic risks a wrong
type nobody can predict). This document now states the same fact §6's earlier text did not.

### 6.3 Sensitivity floor and lowering

§6.1's table above is the complete default mapping, taken as the **maximum over the entry's fields**
(`fields::project`). **The user may pin the entry's sensitivity** (`sensitivity` on `entry.create` /
`update` / `rotate`; the string `"auto"` removes the pin), and may pin a field's `masked` — so a pin can lower
what inference would say. The broker enforces nothing about it beyond storing it: sensitivity is metadata that
colours the UI and orders the lists, and **no access decision reads it** (nothing in `crates/brokerd` consults
`sensitivity` to allow or deny). That is deliberate and recorded: if a future decision lets sensitivity gate
two-factor or reveal, **lowering it must become human-only** — an agent that can lower a pin could talk its way
under a gate (`ADR-078`, *Open*). The design's "the UI does not allow lowering below `high` without a confirm"
is a UI control that has not been built.

**Inference is a suggestion, never a decision** (`ADR-012`). Every detection surfaces in the
preview with the inferred type visible and one click to change it, and a type the user did not pick is never
written to the document.

---

## 7. Editing an existing entry

**`built`** (`ADR-078`). Four operations edit the field list of an entry without rewriting the entry's other
fields, all of them `update`-capability, unlocked-only, generation-checked, and each keeping the previous
envelope and its signed snapshot so that `entry.undo` puts the change back:

| Op | What it does |
|---|---|
| `field.add` | appends fields (or inserts them at `position`) — "paste more" appends and never replaces |
| `field.update` | changes one field's `label`, `value`, `type` or `masked`; `"auto"` clears a pin; a changed value or label re-infers a type that is not pinned |
| `field.remove` | removes one field; the last field cannot be removed ("an entry keeps at least one field — remove the entry instead") |
| `field.reorder` | takes the exact permutation of the current field ids |

`entry.update` and `entry.rotate` also reach fields: `value` with `field` (an id) replaces one field's value
and, with `label`, renames it; a bare `value` on an entry with several fields is refused ("entry has N fields;
pass params.field"); `fields` replaces the whole list, an `id` in an item keeping that field's identity.
`entry.update` keeps no history (as it never did); `entry.rotate` does and stamps `rotatedAt`. All of them
require the vault unlocked and check the caller's last-seen `generation` — a stale one returns `conflict` — and
all of them **read the current document first** (they used to need only the node's public key), which is what
keeps labels, ids and pins across an edit. Deleting a whole entry (`entry.remove`) is soft for 7 days — the real,
tested window (`RECOVERY_WINDOW_SECONDS`, `crates/store/src/entry_archive.rs`, `ADR-048`; I-21 is the *node*-level
seal/restore window, a distinct mechanism). **Audit:** an allowed call that names a field records its id in the
detail (`field: f_1a2b3c4d`, or `fields: f_…,f_…` for a narrowed reveal) — never a label or a value
(`crates/store/src/audit.rs`: "**Never recorded:** any value, any field label, any note content").

**Legacy entries.** An entry written by `2.0.0-alpha.6` is read as a single field with id `f_00000000` and an
empty label (rendered `field 1`), its masking, type and sensitivity pinned so that what it showed under alpha.6
is what it shows now (`03_DATA_MODEL.md §3`). The first edit of any kind re-seals it as a version-2 document;
until then nothing about it changes on disk.

---

## 8. What must be tested, and what already is

| # | Requirement | State |
|---|---|---|
| 1 | Round-trip losslessness on generated inputs, including CRLF, lone CR, NUL, emoji, other 4-byte UTF-8 | **`built`** — `P-7`/`P-8` (10,000 cases each, any input up to 300 chars) plus `parser.rs::tests::never_panics_on_pathological_input` (NUL, 1,000-emoji string, long label, degenerate `":"`/`"///"` inputs) and `crlf_and_lone_cr_both_split_lines`. **Not covered by any parser test:** a 1 MiB single field — the 1 MiB case that exists (`envelope.rs::round_trip_empty_and_large`, a unit test, not `P-1` itself — `P-1` only generates up to 4 KiB) is the envelope, not the parser |
| 2 | Every row of §3.2's table produces exactly the stated parse | **`built`** — one named unit test per row in `parser.rs::tests` |
| 3 | A PEM block survives byte-exactly through parse → encrypt → decrypt → display → copy | **`built` up to display.** `P-17` (`p17_parse_seal_open_preserves_every_field`, 1,000 cases, PEM-shaped strategy) spans parse → document → `seal_as` → `open_any` → `decode`; `P-13`/`P-14`/`P-15`/`P-16` cover the document, its totality, the legacy projection and the authenticated payload kind. The display and the concealed copy are the desktop's and are recorded by `RELEASE_VERIFICATION.md` |
| 4 | Leading and trailing spaces in a value survive | **`built`** — `parser.rs::tests::leading_and_trailing_spaces_in_value_survive` (unit) and `label_only_multiline_value_round_trips` (10,000 generated cases, `properties.rs`) |
| 5 | Duplicate labels are preserved, both of them, in order | **`built`** — `parser.rs::tests::duplicate_labels_both_preserved_in_order` |
| 6 | The unstructured-blob case produces one field and loses nothing | **`built`** — `parser.rs::tests::worked_example_c_unstructured_blob` |
| 7 | No code path anywhere in the repo references a predefined field-name list — enforced by a grep gate in CI | **`built`** (`ADR-078`). `crates/core/tests/no_field_schema.rs` (5 tests) greps `crates/` and `apps/desktop/src*` for `TYPE_SCHEMAS`, `schemaForCategory`, `missingSchemaFields`, `orderFieldsBySchema` and `fieldLabelForName` and fails on any hit, and checks behaviourally that a label is free text — empty, any script, a word like `note` valid on any field. It runs inside `cargo test -p credmgr-core` |
| 8 | A document written by this build opens byte-identically for an alpha.6 envelope; a field document is refused by `open`; a flipped version byte fails the tag | **`built`** — `envelope.rs::an_alpha6_version_1_envelope_still_opens_byte_for_byte` (a pinned alpha.6 envelope), `P-15`, `P-16`, I-29 |
| 9 | `hasTotp` does not change the bytes of any document written before it existed | **`built`** — `crates/store/tests/alpha6_golden.rs` (9 tests): a signed manifest, rotation snapshot and removal archive built from the pinned alpha.6 literal load and verify under the new struct |

---

## 9. Connections

| Direction | Document | What flows across |
|---|---|---|
| feeds | `03_DATA_MODEL.md §5` | the inference rules (`infer_field_type`, `infer_entry_type`, `default_sensitivity`, `default_masked`) §6 tabulates in full |
| depends on | `03_DATA_MODEL.md §3` | the built field document (`id`/`label`/`value`/`type`/`masked` per field, sealed as envelope version 2) that §4, §5 and §7 describe and this document's grammar feeds |
| depends on | `03_DATA_MODEL.md §8` | the `ManifestEntry` shape — no `label` column, and `fieldCount` / `hasTotp` as the plaintext projection |
| feeds | `07_TWO_FACTOR.md §6` | the add path a stored TOTP seed goes through (a field typed `totp-seed`), cited there by this document's own §2 |
| feeds | `10_API_AND_MCP.md §4.1b` | the `field.*` namespace and the multi-field shapes of `entry.create`, `entry.create_batch`, `entry.update`, `entry.rotate`, `entry.reveal`, designed against this document's grammar (§3) and preview contract (§5) |
| feeds | `11_MIGRATION.md §5` | the bulk grammar `credmgr import` is distinct from, and the reason `.env` auto-detection is deliberately excluded (§3.5) |
| feeds | `18_ENDPOINT_INDEX.md §1.2` | the `field.*` rows indexed there as `built`, and `entry.create_batch` |
| depends on | `13_TEST_PLAN.md §3` | `P-6`/`P-7`/`P-8`/`P-11`, the property tests §3.4 and §6 cite as evidence |
| depends on | `14_DECISIONS.md` | `ADR-011` (schemas deleted), `ADR-012` (inference suggests, never decides), `ADR-013` (one entry, many fields, preview-toggle split), `ADR-014` (colon-space rule), `ADR-038` (the `WS*` ambiguity resolved toward the prose), `ADR-048` (the 7-day soft-delete window `entry.remove` uses), `ADR-058`/`ADR-059`/`ADR-060` (this rewrite's own header, vocabulary and figure contract), `ADR-073` (`entry.create_batch`), `ADR-078` (the field model: the document, envelope version 2, `field.*`, the note entry) |

## 10. Source

**Design.** `ADR-011`, `ADR-012`, `ADR-013`, `ADR-014`, `ADR-038`, `ADR-048`, `ADR-073`, `ADR-078` in `14_DECISIONS.md`;
`ADR-058`/`ADR-059`/`ADR-060` for this document's own contract.

**Code.** `crates/core/src/parser.rs` (the bulk grammar: `parse_bulk`, `parse_bulk_segments`);
`crates/core/src/fields.rs` (the field document, its validation, `project`, `from_legacy`, every pure edit);
`crates/core/src/inference.rs` (`FieldType`, `EntryType`, `infer_field_type`, `infer_entry_type_labelled`,
`default_masked`, `default_sensitivity`, `Sensitivity` — built and exhaustive);
`crates/core/src/envelope.rs` (`PayloadKind`, `seal_as`, `open_any`); `crates/brokerd/src/entry_doc.rs` and
`crates/brokerd/src/ops.rs` (`entry.create` / `create_batch` / `get` / `reveal` / `update` / `rotate` and the four
`field.*` arms); `crates/store/src/manifest.rs::ManifestEntry` (`field_count`, `has_totp`; no `label` field);
`crates/cli/src/fields.rs` (`credmgr field`, `set --bulk`); `apps/desktop/src-tauri/src/fields_preview.rs`
(the local preview); `crates/mcp/src/tools.rs` (the field tools' schemas).

**Tests.** `crates/core/tests/field_doc.rs` — `P-13` (`p13_field_doc_round_trips`, 1,000 cases), `P-14`
(`p14_decode_is_total`, 10,000) and `P-14b` (1,000 mutated valid documents — the companion runs 1,000 rather
than 10,000 because 10,000 took over 200 s in a debug build), `P-15` (`p15_legacy_projection_is_preserved`, 1,000),
`P-16` (`p16_payload_kind_is_authenticated`, 1,000), `P-17` (`p17_parse_seal_open_preserves_every_field`, 1,000),
`P-18` (`p18_segments_flatten_to_parse_bulk`, 10,000); `crates/core/tests/no_field_schema.rs`;
`crates/core/tests/properties.rs` — `P-6` (`p6_case_a_round_trips`, 10,000 cases), `P-7` (`p7_parse_is_total`,
10,000), `P-8` (`p8_parse_is_deterministic`, 10,000), `P-11` (`p11_inference_never_mutates_value`, 1,000), and
`label_only_multiline_value_round_trips` (10,000). `crates/core/src/parser.rs`'s own
`#[cfg(test)] mod tests` — one named test per §3.2 row and per §3.3 worked example, plus
`never_panics_on_pathological_input`, `crlf_and_lone_cr_both_split_lines`,
`duplicate_labels_both_preserved_in_order`, `leading_and_trailing_spaces_in_value_survive`.
`crates/core/src/inference.rs`'s own test module — `private_key_wins_over_label`,
`url_in_password_labelled_field_is_still_url`, `seed_phrase_by_word_count`, `totp_seed_base32`,
`api_key_patterns`, `host_and_port_and_username`, `plain_text_fallback`, `masking_defaults`,
`entry_type_wallet_and_server`, `inference_never_mutates_the_value`, and the R0/R1 rules. **Not independently
unit-tested:** `certificate` detection, and the label-only fallbacks for `password` and `api-key`
(rules 10–11) — each is reachable only through the priority chain the other tests exercise, not
through a test naming that rule directly. `crates/brokerd/tests/field_model.rs` (27 broker tests),
`field_seal_joint.rs`, `seal_digest.rs`, `isolation.rs` I-27…I-29; `crates/cli/tests/fields_cli.rs` (10);
`crates/store/tests/alpha6_golden.rs`; `apps/desktop/src-tauri/tests/fields_preview.rs` (6) and `real_broker.rs`;
`scripts/e2e-fields.sh` (the real binaries, including the segment that opens an alpha.6 vault).

**Verification.** `python3 -m tools.corpus_check crossrefs` — every `NN_NAME.md §S` reference
above resolves. `cargo test --workspace -- --list`: 813 tests in 50 test binaries (2026-10-03), includes every
test named above; the last full run recorded: 571 passing, 0 failing, 41 test binaries (2026-10-02; earlier: 448 passing, 37 test binaries on 2026-09-24, re-measured 2026-10-01; 406
passing, 35 test binaries on 2026-09-13 — run `34743281942`; 397 passing, verified 2026-08-18).

**Figure.** `paste-to-sealed-document` (§3) — `docgen`, `kind: "flowchart"`, spec at
`v2/docs/08_FIELD_MODEL_spec.json` (the spec beside the document is the figure's single source, `ADR-060`),
rendered inline by `python3 -m tools.docgen.cli build v2/docs/08_FIELD_MODEL.md --formats html,json`. It
replaces `parser-built-broker-unwired`, which drew the parser with no wire to a broker op; every node and edge of
the new figure is re-derived from source on 2026-10-03: `grep -rn "parse_bulk" crates/ apps/desktop/src-tauri/src`
(callers: `crates/cli/src/fields.rs`, `apps/desktop/src-tauri/src/fields_preview.rs`);
`crates/brokerd/src/ops.rs` (`entry.create`'s arm → `entry_doc::seal_doc` → `envelope::seal_as`);
`crates/store/src/manifest.rs` (the projection fields).
