<div align="center">

# CredMgr

**A local, offline credential vault for developers and their AI agents.**

Encrypted at rest · no hosted account · no telemetry
CLI · web dashboard · Node SDK · **MCP server**

Current source version: **1.9.1**. See [publication readiness](PUBLICATION_READINESS.md)
for the reviewed V1 hardening, release status, and remaining gates.

[Install](#install) · [Quick start](#quick-start) · [AI agents](#ai-agents) ·
[Security](SECURITY.md) · [Privacy](PRIVACY.md) · [Changelog](CHANGELOG.md)

</div>

---

## Why

Your API keys are in a `.env` file. Your VPS password is in a note. Your seed phrase is in a
file called `important.txt`. Your AI coding assistant reads all of them, because they are
sitting in the repository it was pointed at.

CredMgr replaces that with one encrypted vault that the CLI, your dashboard, your scripts and
your AI agents all read from — **by name, at the moment of use**, never by copying the value
somewhere it will be forgotten.

```bash
credmgr get ACME_API_KEY          # value on stdout, nothing written anywhere
```

## What it is not

- **Not a hosted vault service.** There is no hosted account or automatic sync. Your vault is a directory
  on your machine.
- **Not a team tool.** Single user, single machine, by design.
- **Not tracking you.** No telemetry, analytics, crash reporting, or automatic
  update ping — see [PRIVACY.md](PRIVACY.md) for local HTTP and explicit transfers.

## Install

Requires **Node ≥ 18** and [`age`](https://github.com/FiloSottile/age).

```bash
brew install age            # macOS
sudo apt install age        # Debian/Ubuntu
winget install FiloSottile.age   # Windows
```

```bash
git clone https://github.com/FreeXStudio-Platform/credmgr.git
cd credmgr/v1
npm ci
npm link                    # puts `credmgr` on your PATH
credmgr init
```

A V1-only source archive has the package at its top level. Extract it, enter
that directory, and run `npm ci`. For Git-based development and its pretest
guard, initialize a new local repository there with `git init`; the archive
contains no Git history. Keep test vaults outside that repository.

`credmgr init` creates your vault **outside** the repository, in your platform's user-data
directory. Check it with `credmgr where`. It will refuse to create a vault inside a git
working tree.

## Quick start

```bash
credmgr set ACME_API_KEY --stdin    # read the value from stdin
printf '%s' "$TOKEN" | credmgr set ACME_DEPLOY_TOKEN --stdin

credmgr get ACME_API_KEY            # read it
credmgr get ACME_API_KEY --clipboard  # copy it, auto-clears in 30s
credmgr get --ref=3060              # use an actual ref from your vault

credmgr list --project=acme
credmgr search "supabase"
credmgr rotate ACME_API_KEY         # replace, keeping history
credmgr rm OLD_KEY                  # soft delete, recoverable for 7 days
credmgr undo <change-id>

credmgr export acme > /tmp/.env     # a project as a .env bag
credmgr dashboard                   # the web UI
credmgr audit                       # health report
credmgr verify && credmgr doctor    # integrity + repair
```

## How it works

```
   store/index.json     metadata — names, projects, categories, refs.  PLAINTEXT,
                        so you can search a locked vault.  No values, ever.
   store/vault.age      every value, encrypted with age (X25519 + ChaCha20-Poly1305)
   .credmgr/master.key  your age identity.  Never leaves your machine.
   .credmgr/changelog/  7 days of encrypted history, so any change is undoable
```

Values are encrypted in vault storage. Explicit export, file extraction, or
transfer operations can write plaintext to their chosen destinations. Every
credential carries a **sensitivity** (`low` → `critical`) which determines how it may be
displayed, logged and handled — including by AI agents.

## AI agents

CredMgr ships an **MCP server**, so an assistant can fetch a credential at the moment it needs
one instead of you pasting it into a chat.

```json
{ "mcpServers": { "credmgr": { "command": "node", "args": ["/path/to/credmgr/v1/mcp/server.js"] } } }
```

Tools: `credmgr_get` · `credmgr_list` · `credmgr_search` · `credmgr_get_metadata` ·
`credmgr_set` · `credmgr_rotate` · `credmgr_remove` · `credmgr_undo` ·
`credmgr_recent_changes` · `credmgr_list_projects`

Some things deliberately have **no tool at all** — they are absent, not merely gated:
purging the changelog, shortening the 7-day recovery window, or reading the raw change
history. These restrictions apply to the MCP tools, not to an agent with local
shell access as the vault's operating-system user.

Read-only mode: `node mcp/server.js --read-only`.

V1 project names are filters, not access boundaries. An MCP client can read
the whole vault; write tools are enabled by default. Use a separate vault with
only the credentials that client needs. Read-only mode prevents writes but does
not restrict value reads to a project. The dashboard PIN does not block a local
CLI or MCP process running as your operating-system user.

Stdio MCP runs on the same machine as its client. It does not connect a cloud
assistant to a vault on your laptop. Use an authorized local MCP client or
narrowly scoped credentials in secure cloud settings. Never paste secrets into chat.

## Configuration

| | |
|---|---|
| `CREDMGR_HOME` | override the vault location |
| `<vault>/.credmgr/config.json` | retention, dashboard port, auto-classify |
| `<vault>/.credmgr/classify.rules.json` | **your** project rules — never in this repo |

Auto-classification maps credential names to a project, category and sensitivity. The
built-in rules are vendor-neutral (`SUPABASE_`, `AWS_`, `_PRIVATE_KEY`, …); anything specific
to your projects goes in `classify.rules.json`, which is loaded first and always wins.

Daemon token precedence is `--token`, then `CREDMGR_TOKEN`, then the saved token.
Running daemons immediately follow rotation/revocation of a saved token and
stay closed after revocation. A token supplied by a flag or environment variable
remains fixed for that process; change it or stop the process to revoke that
access. CLI token commands use the selected vault's token file, with a legacy
file fallback for existing default installs.

## Never commit a credential

```bash
npm run guard               # scan the whole tree
npm run hooks:install       # install or upgrade the V1 pre-commit guard
```

The vault lives outside the repo, `.gitignore` denies common secret shapes, and
the guard scans the V1 package without printing matched values. The hook works
in both the nested checkout and a standalone V1 repository and scans the bytes
actually staged in Git. `--all` scans current tracked and non-ignored untracked
working files; it does not substitute for the staged scan. Files above 2 MiB,
unresolved index entries, and unreadable files block scanning for review. Binary
files receive content checks too; source and documentation files have no blanket
exemption. This pattern guard is supporting evidence, not a guarantee of clearance.

## Development

```bash
npm test          # 230 checks, including bounded stress, in a disposable vault
npm run guard
```

Contributions welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) first; the bar is
higher than usual because this is a vault.

## Roadmap — V2 "Vault Next"

V2 is a ground-up rewrite in Rust + Tauri, cross-platform, where **each project is a real
cryptographic boundary** rather than a label: per-node keys, one broker process holding all
key material, agent scope derived from the working directory, per-node 2FA, human-only grants
for cross-project reads, and "seal, never delete" removal. V1 remains supported and receives
security fixes.

## Licence

CredMgr is **source-available, not open source**: you may run the current stable release, read and
audit the source, build it to check it against the official release, and report problems or send
patches under [CONTRIBUTING.md](CONTRIBUTING.md). You may not fork, modify or redistribute it.
It is free to use today; future versions may be paid. The terms are in [LICENSE](LICENSE); the
**CredMgr** and **FreexStudio** names and marks are covered by [TRADEMARKS.md](TRADEMARKS.md).
Permissions and commercial arrangements: Admin@freexstudio.com.

Published by **FreexStudio**. If CredMgr saved you from a leaked key, see [DONATE.md](DONATE.md).
