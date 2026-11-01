---
id: V2-017
classification: public
title: Airlock and LLM access
audience: technical
owner: credmgr-v2
status: verified-current
export_allowed: true
surface: repo
last_reviewed: 2026-08-18
---

<!-- artifact-hardened: NEEDS RE-HARDENING — corrected 2026-08-18 (Session 21, after the freeze
     was lifted). The previous stamp (Approved With Known Risks @ d15a5c7) attested to a body that
     described FOUR features that exist in no form — `credmgr prompt`, `credmgr mcp --print-config`,
     a per-node `SecurityLevel`, and the `CREDMGR.md` / `docs/AGENT_CONTRACT.md` pair — across nine
     present-tense lines with one hedging marker in the whole file. Each is now marked `planned`
     with its target design kept, and the A-1/A-2 rows no longer claim CI checks that no workflow
     performs. Every claim was re-derived from `crates/` in this pass: `"prompt"` is not among the
     19 top-level CLI arms; `cmd_mcp()` takes no arguments; `SecurityLevel`/`security_level` appears
     nowhere; neither named file exists at any path. This document was withheld from the corpus
     rewrite earlier the same day on the belief that an external team was building from a copy of
     it. That belief was false, and the withholding protected nobody. -->
# The airlock, and LLM integration

`CredMgr V2` · Pass 3 · `2026-08-05`

> **The rule, in one line:** everything flows *inward through one door*. Nothing inside the
> vault ever reaches outward, and nothing reaches in except through that door.

---

## 1. The airlock

```
   OUTSIDE  ─────────────────────────────────────────────►  INSIDE
   the world                    ONE DOOR                    the vault

   ┌──────────┐   ┌──────────┐   ┌──────────┐  ╔═══════════╗   ┌──────────┐
   │ human UI │   │   CLI    │   │   LLM    │  ║           ║   │ node keys│
   │          │   │          │   │ via MCP  │  ║  BROKER   ║   │ envelopes│
   └────┬─────┘   └────┬─────┘   └────┬─────┘  ║  credmgrd ║   │ notes    │
        │              │              │        ║           ║   └──────────┘
        └──────────────┴──────────────┘        ╚═════╤═════╝
                       │                             │
                  request in ────────────────────────┘
                  answer out ◄─── one value, one request, logged

   ╳ NO outbound network        ╳ NO telemetry        ╳ NO cloud sync
   ╳ NO plugin can load inside  ╳ NO listening port   ╳ NO auto-update of the vault
```

**Six invariants.** A-1 and A-2 hold **structurally** today — verified by inspection, not by a
gate: no HTTP client is linked into `credmgrd` and `crates/` contains no TCP listener at all.
The *automated* enforcement each row describes is **`planned`**: `13_TEST_PLAN.md` contains no
airlock test, and `.github/workflows/` performs neither the binary scan nor the bind-scan. The
"Enforced by" column below therefore states the intended mechanism, not a running one.

| # | Invariant | Enforced by |
|---|---|---|
| **A-1** | The vault process makes **no outbound network connection, ever** | No HTTP client is linked into `credmgrd` at all. Asserted by `cargo deny` bans of HTTP client, server and TLS crates in `v2/deny.toml` and `apps/desktop/src-tauri/deny.toml` (and `apps/desktop/src-tauri/tests/dependency_policy.rs` for the shell); the CI workflow that runs it has not yet run on this release (billing, GitHub issue 33). Re-checkable by hand: no HTTP client is linked into `credmgrd`. Not a policy — an absent capability. |
| **A-2** | Nothing listens on a network interface | UDS / named pipe only. The bind-scan is **`planned`** — no workflow performs it; the HTTP-server crates are banned by `cargo deny` and `crates/` contains no TCP listener, which is why the property holds regardless. |
| **A-3** | The only ingress is the broker socket, and every caller is identified before its first byte is parsed | Peer uid/SID check (`16_CROSS_PLATFORM.md §5.2`, macOS/Linux; `§5.3`, Windows) |
| **A-4** | No code outside the vault can load *inside* it | No plugin system, no `dlopen`, no scripting engine, no user-supplied regex compiled into the broker. (V2 has no classify subsystem and no regex engine in any process — the CLI-side rule about where classify rules run describes V1.) |
| **A-5** | A value leaves only as the answer to one identified, authorised, logged request | `10 §1`; values appear in exactly two response types |
| **A-6** | The updater updates the *app*, never the *vault*, and is signed + opt-in | `21_RELEASE_AND_INTEGRITY.md` |

**Why "no outbound network" is the load-bearing one.** Every other control is about who may
*ask*. A-1 is about where an answer can *go*. A vault that cannot phone home cannot exfiltrate,
cannot be silently backdoored into a sync service, and cannot leak through telemetry. It is
the single property that makes "your secrets stay on your machine" a fact rather than a
marketing line — so it is enforced by *not linking an HTTP stack*, which no configuration
mistake can undo.

---

## 2. Security levels — the user's choice

One setting, three levels, stated in consequences rather than jargon. Default is **Guarded**.

| | **Open** | **Guarded** *(default)* | **Sealed** |
|---|---|---|---|
| Agent may `list` / `read` metadata in its node | ✅ | ✅ | ✅ |
| Agent may `reveal` low/medium values | ✅ | ✅ | ⏸ approval |
| Agent may `reveal` high/critical values | ✅ | ⏸ **approval-on-demand** | ⏸ approval |
| Agent may `create` | ✅ | ✅ (pending tray) | ⏸ approval |
| Agent may `update` | ✅ | ✅ | ⏸ approval |
| Cross-node reads | ❌ grants only | ❌ grants only | ❌ grants only |
| Orphan reads | ❌ never | ❌ never | ❌ never |
| Typical wait | none | one tap, on the ~5% of fetches that matter | one tap each |

Three things **no level ever changes**, because they are the product rather than a preference:
cross-node isolation, orphan sealing, and the human-only nature of grants.

**`planned`.** No security level exists in any form: `SecurityLevel`/`security_level` appears
nowhere in `v2/crates/`, at either scope, so the whole table above is target design rather than a
setting a user can change today. The intended behaviour is that the setting **will be** per-node as
well as global — a wallet node sitting at Sealed while everything else is Guarded.

---

## 3. Installation → wired agent, simulated end to end

What actually happens, from download to a working agent. This is the flow Sonnet 5 builds.

```
 1  DOWNLOAD    user gets credmgr-2.0.0.dmg / .msi / .AppImage from GitHub Releases
                app verifies its own signature + SHA256SUMS on first launch

 2  FIRST RUN   ┌ create vault ── name ────────────────────────────────────┐
                │ protect it ──── platform keystore detected: "Secure      │
                │                 Enclave (Hardware)" · passphrase (req'd) │
                │ recovery ────── 256-bit code shown once, must confirm    │
                │ two-factor ──── TOTP enrol + 10 recovery codes           │
                │ security level ─ ● Guarded  ○ Open  ○ Sealed             │
                └──────────────────────────────────────────────────────────┘

 3  NODES       "Scan a folder for projects?"  →  user picks ~/code
                finds 6 git repos → offers one node each, workdirs pre-filled
                nothing is created without a tick

 4  CONNECT     Settings → LLM Integration          ← the screen that matters
                ┌──────────────────────────────────────────────────────────┐
                │ DETECTED ON THIS MACHINE                                 │
                │  ✅ Claude Code        ~/.claude.json          [Connect] │
                │  ✅ Claude Desktop     …/claude_desktop_config.json      │
                │  ✅ Cursor             ~/.cursor/mcp.json      [Connect] │
                │  ✅ VS Code (Copilot)  …/mcp.json              [Connect] │
                │  ⚪ Windsurf           not installed                     │
                │  ⚠️ ChatGPT Desktop    connector — see §5.3      [How…]  │
                │                                                          │
                │  [ Connect all ]            [ Copy the vault prompt ]    │
                └──────────────────────────────────────────────────────────┘

 5  ONE CLICK   Connect writes the MCP entry (backing up the file first),
                drops CREDMGR.md into each node's work folder, and copies
                the Vault Protocol prompt to the clipboard.

 6  WORKING     agent in ~/code/acme runs `credmgr_whoami`
                → { node: "acme", can_reach: ["acme", "global"], level: "guarded" }
                agent asks for a value → returned, or one tap → returned
                agent asks for another project's value → structured refusal
```

---

## 4. Auto-configuring MCP

### 4.1 What "Connect" will do — **`planned`**

No Settings screen triggers this (the app's Settings has no Agents or LLM section; `RELEASE_VERIFICATION.md` lists the sections that exist),
and a repo-wide grep
finds no code anywhere in `v2/crates` that writes an `mcpServers.credmgr` config block or a
`.credmgr-backup-<ISO8601>` file. `10_API_AND_MCP.md §3.4` describes the same mechanism, entirely
in future tense. The target design:

```
1  will locate the client's config file      (table in §4.2)
2  will copy it to <file>.credmgr-backup-<ISO8601>  ← always, before any write
3  will parse; if it is not valid JSON, will STOP and show the file, never overwrite
4  will merge, never replace:
       config.mcpServers.credmgr = {
         command: "<abs path to the credmgr binary>",
         args: ["mcp"]
       }
   every other key will be left byte-identical (2-space JSON, key order preserved)
5  will write atomically (temp + fsync + rename)
6  will verify by re-reading and re-parsing
7  will record the change in the audit log, and will offer one-click Undo
```

**Never** will it: touch a key it did not add · reformat the file · write an API key into a
config · configure a *remote* MCP server · run while the file is open in an editor with
unsaved changes (it will check mtime around the write and abort on a race).

### 4.2 Client detection matrix

| Client | Config path | Mechanism |
|---|---|---|
| **Claude Code** | `~/.claude.json` → `mcpServers` | stdio MCP. One global entry; cwd decides the node (`10 §3.4`). |
| **Claude Desktop** | macOS `~/Library/Application Support/Claude/claude_desktop_config.json` · Windows `%APPDATA%\Claude\claude_desktop_config.json` · Linux `~/.config/Claude/…` | stdio MCP |
| **Cursor** | `~/.cursor/mcp.json` (or `<project>/.cursor/mcp.json`) | stdio MCP |
| **VS Code / Copilot** | `<project>/.vscode/mcp.json` or the user `mcp.json` | stdio MCP |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` | stdio MCP |
| **Zed** | `~/.config/zed/settings.json` → `context_servers` | stdio MCP |
| **ChatGPT Desktop** | — | No local stdio MCP config to write. See §5.3. |
| **Anything else** | — | **`planned`** — `credmgr mcp --print-config` does not exist; `cmd_mcp()` takes no arguments at all and the dispatch arm discards the remaining argv |

Detection is by **file existence plus a parse check**, never by process scanning, and a client
that is present but unconfigured is shown as such rather than silently skipped.

### 4.3 `CREDMGR.md` — the file that teaches any agent, with no MCP at all

**`planned`.** No `CREDMGR.md` exists anywhere in this repository, nothing generates one, and no
code path writes one into a work folder. The whole of §4.3 is target design; the present tense
below describes how it **will** behave once built.

It will be dropped into each node's work folder (with consent, and never overwriting an existing one
without showing a diff). Claude Code reads it as project context; Cursor and Copilot pick it
up as repo context; a human can paste it into anything.

This is the **fallback that always works**: even with zero MCP support, an agent that can read
the repo learns the rules and can shell out to the CLI.

---

## 5. The Vault Protocol prompt

### 5.1 What it is

One block of text that turns any competent LLM into a correct citizen of the vault. It states
the topology, the scope rules, the exact commands, and — most importantly — **what to do when
refused**. It is generated per-vault (it knows your node names and your security level), and
**`planned`** in all three of its delivery routes: the Settings screen does not exist (there is no
UI at all), `credmgr prompt` is not a subcommand — the 24 top-level arms in
`crates/cli/src/main.rs` do not include it — and `CREDMGR.md` is not generated by anything (§4.3).

### 5.2 The prompt (generated; `{{…}}` filled from the live vault)

```markdown
## Credential access — CredMgr vault protocol

This machine stores every secret in a local encrypted vault called **credmgr**.
Secrets are NOT in .env files, NOT in the repo, and NOT in your context. Get them
from the vault at the moment you need them.

### Where you are
You are scoped to the node **{{node}}**. You can reach: {{reachable}}.
Security level: **{{level}}**.

### How to read a credential
    credmgr get <NAME>              # value on stdout, nothing logged
    credmgr get <NAME> --json       # value + metadata
    credmgr list                    # everything you can see (names only)
    credmgr search <term>
    credmgr whoami                  # your node, scope, and limits
With MCP available, prefer the tools: credmgr_get, credmgr_list, credmgr_search,
credmgr_whoami.

### How to write one
    credmgr set <NAME>              # value from stdin — NEVER as an argument
    echo "$VALUE" | credmgr set <NAME>
    credmgr rotate <NAME>           # replaces a value, keeps history

### Rules you must follow
1. NEVER print a secret value into chat, a log, a commit message, a comment, or a
   file. Pipe it. If you must show it, show `••••` and the last 4 characters.
2. NEVER put a secret in a command-line argument — it lands in shell history and
   in `ps` output. stdin, always.
3. NEVER copy a secret into the repository, an .env file, or a config you commit.
   Reference it by NAME. If code needs it at runtime, read it from the vault or
   from an environment variable the operator sets.
4. NEVER try to reach another project's node. You cannot, and attempts are logged.
5. If you are refused, the refusal tells you why and what would fix it. Do not
   retry, do not rephrase, do not look for another route. Tell the operator what
   you need and why, in one sentence, and continue with everything else.
6. If the vault is locked you may get `approval_pending`. That is normal: the
   operator gets a one-tap prompt. Wait, or carry on with other work.
7. Fetch what you need EARLY, not in the middle of a long run.

### What you will never be able to do
Create a grant · read another node · read sealed/orphaned data · read a 2FA seed
(you can get a current 6-digit code) · change your own permissions · purge the
audit log. These are absent, not merely gated. Asking differently will not help.

### If a secret does not exist yet
Do not invent one and do not put a placeholder in the code. Say exactly which
credential is missing and what it is for, and let the operator add it.
```

### 5.3 One-click delivery

| Target | Mechanism |
|---|---|
| Claude Code / Cursor / Copilot / Windsurf | **`planned`** — `CREDMGR.md` in the work folder, read automatically. The file does not exist yet (§4.3) |
| Claude Desktop | MCP tool descriptions carry a condensed form; **Copy prompt** for the rest |
| **ChatGPT Desktop / web** | **Copy prompt** → paste once into a Project's custom instructions. It has no local stdio MCP config to write, so the honest UI says: *"ChatGPT cannot be wired automatically — paste this into your Project instructions."* |
| Anything else | **`planned`** — `credmgr prompt` is not a subcommand |

**No "send to LLM" button that silently transmits anything.** The vault has no outbound
network (A-1), so it *cannot* post your prompt to an API even if asked — delivery is always
the clipboard, a local config file, or a file on disk. That is a deliberate limitation and it
is the honest one: a button that appeared to send would need a network stack, and that stack
would be the hole.

---

## 6. The agent-facing contract, in the repo

Three artefacts ship so that an agent understands the boundary without being told:

| File | Where | Purpose |
|---|---|---|
| `CREDMGR.md` | each node's work folder | **`planned`** — does not exist; nothing generates it |
| `docs/AGENT_CONTRACT.md` | the credmgr repo | **`planned`** — this file does not exist at any path in the repository |
| tool descriptions | the MCP server itself | condensed rules, so an agent that reads nothing else still gets them |

The code states it too — the MCP server file carries the forbidden-tools list in its header
(`10 §3.2`), and test **I-13** enumerates the live tool registry so a future contributor who
adds `credmgr_grant_create` gets a red test explaining why it must not exist.

---

## 7. New risks from this surface

| ID | Risk | Bound | Mitigation |
|---|---|---|---|
| **AR-11** | Writing another app's config file could corrupt it | Backup before every write; parse-verify after; atomic rename; one-click undo | Never write a file that fails to parse first |
| **AR-12** | A prompt-injected agent follows instructions from a scraped page instead of the protocol | It still cannot cross a node, create a grant, or read a seed — the boundary is enforced in the broker, not in the prompt | The prompt is guidance; §1's invariants are the control |
| **AR-13** | "Open" level users get no approval prompts | Their explicit choice, stated in consequences; cross-node isolation still absolute | Default is Guarded; Open shows a persistent Security-panel badge |
| **AR-14** | `CREDMGR.md` in a repo tells an attacker a vault exists | It contains no secret, no path, no node the reader cannot already see | Accepted — the operational value far exceeds it |

---

## 8. Connections

| Direction | Document | What flows across |
|---|---|---|
| depends on | `06_ACCESS_GRAPH.md §3` | the seven-capability enum §1's A-5 invariant and §5's client rules are gated against |
| depends on | `10_API_AND_MCP.md §3.1`–`§3.2` | the 15 MCP tools and the forbidden-tool list §1's A-4 and §6 both cite |
| depends on | `10_API_AND_MCP.md §3.4` | the target design for auto-configuring MCP that §4.1 restates at the file-procedure level |
| depends on | `16_CROSS_PLATFORM.md §5.2`–`§5.3` | the peer uid/SID mechanism that backs A-3's "identified before its first byte is parsed" |
| depends on | `21_RELEASE_AND_INTEGRITY.md §2` | the signed, opt-in update channel A-6 depends on |
| feeds | `05_THREAT_MODEL.md §2` | the agent adversary (A2) this whole document exists to bound |
| feeds | `13_TEST_PLAN.md §4.6` | test I-13, which enumerates the live MCP tool registry and fails if a forbidden tool appears |
| feeds | `00_README_START_HERE.md §6` | the security chain's fifth and last link, A-1's no-outbound-network invariant |

## 9. Source

**Design.** `ADR-019` (no HTTP surface, the reason A-1/A-2 are structural rather than
configured); `ADR-059` (the `built`/`partial`/`planned` vocabulary this document's own §4.1
correction applies).

**Code.** `crates/brokerd/` — no `reqwest`/`hyper`/`curl` dependency anywhere in its
`Cargo.toml`, the fact A-1 rests on. `crates/mcp/src/tools.rs` — the forbidden-tools list in its
header and the 15-tool registry. `crates/brokerd/src/peer.rs` — the peer-identification code A-3
cites.

**Tests.** `crates/brokerd/tests/isolation.rs::i13_*` — enumerates the live MCP tool registry
and fails red if a forbidden tool (grant creation, orphan read, TOTP seed, policy change, audit
purge) ever appears.

**Verification.** `grep -rn "mcpServers.credmgr\|llm_connect\|llm\.connect" v2/crates v2/apps` —
zero matches, the evidence behind §4.1's `planned` marking. `grep -rn "reqwest\|hyper\|curl" v2/crates/brokerd/`
— zero matches, the evidence behind A-1.
