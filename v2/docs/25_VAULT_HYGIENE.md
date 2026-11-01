<!-- artifact-hardened: NEEDS RE-HARDENING — new design record, 2026-10-31; not yet reviewed in a second pass -->
# 25 · Vault hygiene: the doctor's organising scan, and importing from V1

**Status: planned (the importer exists, `tools/v1-to-v2/migrate.js`; the scan does not).** Decision: `ADR-097`.

## 1. What the scan looks for

It runs in the broker over unlocked nodes the caller can read, and returns names, node ids and reasons. A value never leaves the broker and is never in a report.

| Finding | How it is detected | Proposal |
|---|---|---|
| Exact duplicate secret | a keyed hash of each field value (per-run key, discarded) matches across entries or nodes; values under 8 characters and well-known placeholders are ignored | keep one entry, link the rest, or delete after confirmation |
| Same-seed wallets | the same normalised seed phrase in several entries; or the same private key | one *wallet* entry holding the seed once and one account per derivation path and chain, each account showing its path and address |
| Near-duplicate names | edit distance and separator-insensitive match (`AKIDO_` and `AIKIDO_`) | rename or merge |
| Not a secret | the value is a URL, hostname, e-mail, IP, port, boolean, number or low-entropy short text and the name does not say key, token, secret or password | retype as `config`, unmask, and offer to move it to a project `.env.example` |
| Notes filed as secrets | multi-line prose over 1 KB | convert to a node note |
| Empty or placeholder | empty, `changeme`, `todo`, `xxx` | delete or fill |
| Retired or expired | `RETIRED` in the name, past `expiresAt`, or not rotated for a year | archive or rotate |
| Index drift | an index row with no stored value, or the reverse (`credmgr doctor` already repairs what is safe) | report; repair what is safe |
| Misfiled scope | names carrying a project prefix that sit in `global` | propose the project node (global is readable by every project) |

## 2. Rules

The scan only proposes. Applying a proposal is an ordinary audited write by the signed-in user; deleting is always the soft delete with 7-day undo. It never runs without an unlocked login, and an agent token gets the counts only. A report is held in memory and never written to disk.

## 3. Importing from V1

Run `node tools/v1-to-v2/migrate.js` for a dry-run plan, then `CREDMGR_TOKEN=... node tools/v1-to-v2/migrate.js --apply`. One V1 project becomes one node; names that point at the operator-sealed machine are skipped unless `--include-sealed`. V1 is only read. After the copy, run the scan in the app and apply what you accept.
