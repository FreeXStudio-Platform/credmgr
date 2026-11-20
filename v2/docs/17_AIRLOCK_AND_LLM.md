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

<!-- 2026-11-06: §2, §3, §4, §5 and §6 rewritten from `planned` to the built state (ADR-140, ADR-141, ADR-142, ADR-143); the
     `llm.*` broker operations and the duress code are dropped (ADR-146, ADR-145) and the machine lock is defined and not built
     (ADR-144). The stamp below still does not hold: the body changed again and has not been through the passes. -->
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

**Six invariants.** A-1 and A-2 hold **structurally** — no HTTP client is linked into `credmgrd`
and `crates/` contains no TCP listener at all — and, since ADR-156, they are also **checked by a
gate**: `v2/scripts/airlock-check.sh` scans the built binary (A-1) and runs the real broker on a
throwaway vault to prove it holds no internet socket (A-2). It runs in the `v2-airlock` job of
`security.yml` and in the local gate script. The other rows' "Enforced by" column states the
mechanism each relies on; where it says `planned`, it is the intended one, not a running one.

| # | Invariant | Enforced by |
|---|---|---|
| **A-1** | The vault process makes **no outbound network connection, ever** | No HTTP client is linked into `credmgrd` at all. Asserted by `cargo deny` bans of HTTP client, server and TLS crates in `v2/deny.toml` and `apps/desktop/src-tauri/deny.toml` (and `apps/desktop/src-tauri/tests/dependency_policy.rs` for the shell); the CI workflow that runs it has not yet run on this release (billing, GitHub issue 33). **Binary scan (ADR-156):** `scripts/airlock-check.sh` fails if the built `credmgrd`'s symbols name `TcpListener`, `TcpStream`, `UdpSocket` or an HTTP/TLS stack, or if it links a TLS or HTTP library dynamically. Not a policy — an absent capability. |
| **A-2** | Nothing listens on a network interface | UDS / named pipe only. **Bind-scan (ADR-156):** `scripts/airlock-check.sh` starts the real `credmgrd` on a throwaway vault and fails if it holds any TCP, UDP or raw socket (v4 or v6) just after start, or after init, unlock and an entry written and read back (`lsof`, or `/proc` on Linux). It first proves its detector sees a known `127.0.0.1` listener. Linux CI only; on macOS the same script runs by hand. |
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

## 2. Security levels — the user's choice — **`built`** (ADR-140)

One setting **per node**, three levels, stated in consequences rather than jargon. New nodes, and a node
from a vault written before the setting existed, are **Guarded**. The level binds an *agent* (an agent
token or a caller identified by its folder); the owner's own login is never held by it. The level of the
node being read or written applies, so a read through a grant is held by the level of the node it reads.

| | **Open** | **Guarded** *(default)* | **Strict** (stored as `sealed`) |
|---|---|---|---|
| Agent may `list` / `read` metadata in its node | ✅ | ✅ | ✅ |
| Agent may `reveal` low/medium values | ✅ | ✅ | ⏸ approval |
| Agent may `reveal` high/critical values | ✅ | ⏸ **approval-on-demand** | ⏸ approval |
| Agent may get a TOTP code | ✅ | ✅ | ❌ refused (the owner reads it) |
| Agent may `create` | ✅ | ✅ | ⏸ held in the tray until the owner accepts |
| Agent may `update`, `rotate`, `remove`, `restore`, `undo` | ✅ | ✅ | ❌ refused — `node_access_denied`, rule `L1`; the owner makes the change |
| Cross-node reads | ❌ grants only | ❌ grants only | ❌ grants only |
| Orphan reads | ❌ never | ❌ never | ❌ never |
| Typical wait | none | one tap, on the ~5% of fetches that matter | one tap each |

"Approval" is the one-tap path a locked vault already used (ADR-042, ADR-088): the agent sees
`approval_pending`, the owner decides, the value is handed over once. Two cells differ from the first
draft of this table, on purpose (ADR-140 §5–§6): an agent's *edit* is refused rather than approved, because
nothing stages a proposed edit for a decision, and the TOTP code is refused rather than approved, because the
approval path returns the entry and the seed is in it.

The strictest level is called **Strict** for people (ADR-152). The word "sealed" stays with sealing a node into Orphaned (`node.seal`); the stored and wire value of the level is still `sealed`.

Three things **no level ever changes**, because they are the product rather than a preference:
cross-node isolation, orphan sealing, and the human-only nature of grants.

**Setting it.** `credmgr node policy <id> --reason "…" --security-level open|guarded|strict` (`sealed` is accepted too: it is the stored value), or the
"agents here" control in the node inspector. **Lowering** a level lets an agent do more, so it needs the
user's presence (Touch ID) like the other widening policy changes; raising does not. `credmgr_whoami`
reports the caller's own level, and `graph.snapshot` reports every node's.

**Evidence.** `crates/brokerd/tests/security_levels.rs` (10 tests); `apps/desktop/tests/e2e/agents.spec.ts`.

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
                │ security level ─ set per node afterwards (default Guarded) │
                └──────────────────────────────────────────────────────────┘

 3  NODES       "Scan a folder for projects?"  →  user picks ~/code
                finds 6 git repos → offers one node each, workdirs pre-filled
                nothing is created without a tick

 4  CONNECT     Settings → Agents                   ← the screen that matters
                ┌──────────────────────────────────────────────────────────┐
                │ DETECTED ON THIS MACHINE                                 │
                │  ✅ Claude Code        ~/.claude.json     [Copy command] │
                │  ✅ Claude Desktop     …/claude_desktop_config.json      │
                │                                      [Copy] [Connect…]   │
                │  ✅ Cursor             ~/.cursor/mcp.json [Copy] [Connect…] │
                │  ✅ VS Code (Copilot)  …/mcp.json         [Copy] [Connect…] │
                │  ⚪ Windsurf           not installed                     │
                │  Any other assistant                      [Copy JSON]    │
                │                                                          │
                │  [ Copy prompt ]                    [ Copy CREDMGR.md ]  │
                └──────────────────────────────────────────────────────────┘

 5  ONE CLICK   Connect… shows the change as a diff; only the Write button
                writes the MCP entry (backing the file up first). Claude Code's
                own state file is never written: its row copies the one-line
                command. CREDMGR.md goes into a work folder with
                `credmgr agent init`; the Vault Protocol prompt is one Copy away.

 6  WORKING     agent in ~/code/acme runs `credmgr_whoami`
                → { node: "acme", can_reach: ["acme", "global"], level: "guarded" }
                agent asks for a value → returned, or one tap → returned
                agent asks for another project's value → structured refusal
```

---

## 4. Auto-configuring MCP

### 4.1 What "Connect" does — **`built`** (ADR-141, ADR-142)

The decisions are `credmgr_core::agentcfg` (pure text); the CLI (`credmgr agent connect|disconnect`) and the
app (Settings → Agents) read and write the files. Neither writes anything the person has not seen.

```
1  locates the client's config file          (table in §4.2)
2  parses it; if it is not valid JSON, STOPS and shows it, never overwrites
3  plans the merge, never a replace:
       config.mcpServers.credmgr = {
         command: "<abs path to the credmgr binary>",
         args: ["mcp"]
       }                                     (VS Code: servers.credmgr, with "type": "stdio")
   every other byte of the file is left unchanged (the new member is spliced in as text)
   and the result is re-parsed and compared with the original plus exactly that one entry
4  shows the path, the diff and the backup name
5  waits for --yes / a typed y (CLI) or the Write button (app); the app's write carries the token of the
   plan it showed and is refused if the file changed since (`agent_changed`)
6  copies the file to <file>.credmgr-backup-<ISO8601>  ← always, before any write
7  writes through a temporary file (fsync, then rename), keeps the permission bits
8  reads it back and compares; a mismatch is reported with the backup's path
```

**Never:** touch a key it did not add · reformat the file · replace a different `credmgr` entry · write an
API key into a config · configure a *remote* MCP server · write `~/.claude.json` at all (Claude Code's live
state; its row shows `claude mcp add --scope user credmgr -- <binary> mcp` instead).

**Not done, on purpose.** No audit-log record and no one-click undo button: a connect is a file written by
the owner's own process, not a vault decision, and the broker holds no write access to other applications'
files (ADR-146). The backup beside the file is the trail; *Disconnect…* removes the entry.

### 4.2 Client detection matrix

| Client | Config path | Mechanism |
|---|---|---|
| **Claude Code** | `~/.claude.json` → `mcpServers` | stdio MCP. One global entry; cwd decides the node (`10 §3.4`). |
| **Claude Desktop** | macOS `~/Library/Application Support/Claude/claude_desktop_config.json` · Windows `%APPDATA%\Claude\claude_desktop_config.json` · Linux `~/.config/Claude/…` | stdio MCP |
| **Cursor** | `~/.cursor/mcp.json` (or `<project>/.cursor/mcp.json`) | stdio MCP |
| **VS Code / Copilot** | `<project>/.vscode/mcp.json` or the user `mcp.json` | stdio MCP |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` | stdio MCP |
| **Zed** | `~/.config/zed/settings.json` → `context_servers` | **Not included** — its server entry changed shape between releases and was not verifiable (ADR-141); a new row in `agentcfg` adds it |
| **ChatGPT Desktop** | — | No local stdio MCP config to write. See §5.3. |
| **Anything else** | — | **`built`** — `credmgr mcp --print-config` (generic `mcpServers` JSON), and *Any other assistant → Copy JSON* in the app |

`credmgr mcp --print-config [claude-code|claude-desktop|cursor|vscode|windsurf]` prints the exact
configuration in that client's shape on stdout; for Claude Code it adds the one-line command on stderr.
The table's paths are the macOS ones, the platform in scope for 2.0.0.

Detection is by **file existence plus a parse check**, never by process scanning, and a client
that is present but unconfigured is shown as such rather than silently skipped. The states are
`not found`, `not connected`, `connected`, `different entry` (a `credmgr` entry CredMgr did not write) and
`unreadable`.

### 4.3 `CREDMGR.md` — the file that teaches any agent, with no MCP at all — **`built`** (ADR-143)

`credmgr agent init [--node <id>] [--dir <path>] [--yes]` writes it into a node's work folder (the current
folder by default). An existing file is shown as a diff and replaced only with `--yes` or a typed `y`.
The file holds the Vault Protocol prompt of §5.2 filled from the live vault (the node, the nodes it
reaches, its level), how to wire MCP, and the sentence that it contains no secret: node names and rules
only, never a value. Claude Code reads it as project context; Cursor and Copilot pick it up as repo context; a human can
paste it into anything. The app's *Copy CREDMGR.md* puts the same text on the clipboard.

This is the **fallback that always works**: even with zero MCP support, an agent that can read
the repo learns the rules and can shell out to the CLI.

---

## 5. The Vault Protocol prompt

### 5.1 What it is

One block of text that turns any competent LLM into a correct citizen of the vault. It states
the topology, the scope rules, the exact commands, and — most importantly — **what to do when
refused**. It is generated per-vault (it knows your node names and your security level), and
**`built`** in all three of its delivery routes: `credmgr prompt [--node <id>]`, the *Copy prompt* and
*Copy CREDMGR.md* buttons of Settings → Agents, and `CREDMGR.md` (§4.3). All three call
`credmgr_core::agentcfg::vault_protocol_prompt`: names and structure only, never a value.

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
6. You may get `approval_pending`. That is normal: the operator gets a one-tap
   prompt. Wait, or carry on with other work.
7. Fetch what you need EARLY, not in the middle of a long run.

### What you will never be able to do
Create a grant · read another node · read sealed/orphaned data · read a 2FA seed
(you can get a current 6-digit code, except on a Strict node) · change your own permissions · purge the
audit log. These are absent, not merely gated. Asking differently will not help.

### If a secret does not exist yet
Do not invent one and do not put a placeholder in the code. Say exactly which
credential is missing and what it is for, and let the operator add it.
```

### 5.3 One-click delivery

| Target | Mechanism |
|---|---|
| Claude Code / Cursor / Copilot / Windsurf | **`built`** — `CREDMGR.md` in the work folder (`credmgr agent init`), read automatically (§4.3) |
| Claude Desktop | MCP tool descriptions carry a condensed form; **Copy prompt** for the rest |
| **ChatGPT Desktop / web** | **Copy prompt** → paste once into a Project's custom instructions. It has no local stdio MCP config to write, so the honest UI says: *"ChatGPT cannot be wired automatically — paste this into your Project instructions."* |
| Anything else | **`built`** — `credmgr prompt`, or *Copy prompt* in Settings → Agents |

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
| `CREDMGR.md` | each node's work folder | **`built`** — `credmgr agent init` writes it (§4.3) |
| `AGENT_CONTRACT.md` | `v2/docs/` in the credmgr repo | **`built`** — what an agent can and cannot do at each level, and what each refusal means |
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
| depends on | `10_API_AND_MCP.md §3.4` | the registration shape that §4.1 writes, at the file-procedure level |
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

**Added 2026-11-06.** Design: `ADR-140` (security levels), `ADR-141` (client wiring in core), `ADR-142` (connect writes only
on consent), `ADR-143` (Settings → Agents, the prompt, `CREDMGR.md`), `ADR-144` (machine lock: defined, not
built), `ADR-145` (duress code: dropped), `ADR-146` (`llm.*` operations: dropped).

**Code (the airlock's new surface).** `crates/core/src/agentcfg.rs` · `crates/cli/src/agent.rs` ·
`apps/desktop/src-tauri/src/agents.rs` · `crates/core/src/registry.rs::SecurityLevel` ·
`crates/brokerd/src/ops.rs` (`reveal_needs_owner_approval`, `sealed_change_guard`).

**Verification.** `bash v2/scripts/airlock-check.sh` — A-1 and A-2 on the built binary and the running broker. `grep -rn "reqwest\|hyper\|curl" v2/crates/brokerd/` — zero matches, the source-level evidence behind A-1.
The wiring writes files only from the CLI and the app, never from `credmgrd`: `grep -n "agentcfg" v2/crates/brokerd/src`
— zero matches, the evidence behind ADR-146.
