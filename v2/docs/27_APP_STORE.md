<!-- artifact-hardened: NOT HARDENED — first pass (creation) on 2026-11-14 against feat/deferred-quick-wins @ 25f187e for ADR-162. A preparation guide, not source-of-truth: every operator decision in §9 is open and nothing here has been tried on a Mac or with App Review. -->
# CredMgr on the Mac App Store

The Mac App Store (MAS) edition is the second flavour of CredMgr decided in ADR-162: the same vault, broker, CLI
and app, sandboxed, with every identifier in `packaging/mas/identity.conf`. This document holds what the store
needs that is not code: the listing drafts, the questionnaire answers, the screenshot plan, the notes for App
Review, the export-compliance answer and the operator's checklist. **Status (2026-11-14): built and inspected on
Linux only; nothing has been built on a Mac, signed, uploaded or reviewed.** Every Apple-side step is the
operator's (§9).

Everything here is written for CredMgr; no text is taken from another product's listing.

---

## 1. Build and check

| Step | Command | Host |
|---|---|---|
| Build the MAS bundle into `dist-mas/` (unsigned) | `scripts/release-app.sh --mas` | macOS |
| Inspect an assembled `dist-mas/` | `scripts/release-app.sh --mas --verify [DIR]` | any, with python3 |
| The submission gate (final ids, profile embedded) | `scripts/release-app.sh --mas --verify --strict` | any |
| Prove the inspection can fail (29 cases) | `scripts/release-selftest.sh --mas` | any |
| Print the MAS signing steps | `scripts/sign-notarise.sh --mas ... --dry-run` | any |

What goes into the bundle (`tauri.mas.conf.json`, `packaging/mas/`):

| Path in `CredMgr.app/Contents` | What | Sandbox |
|---|---|---|
| `MacOS/CredMgr` | the app | own; app group; two identity keys |
| `MacOS/credmgrd` | the broker, `mas` feature, Info.plist linked in | own (launchd is its parent); app group; **no network** |
| `MacOS/credmgr` | the CLI and MCP server, `mas` feature, Info.plist linked in | own; app group |
| `MacOS/credmgr-presence` | Touch ID / Secure Enclave helper | `inherit` |
| `Library/LaunchAgents/com.credmgr.brokerd.plist` | the `SMAppService` agent, `BundleProgram` `Contents/MacOS/credmgrd` | - |
| `Resources/PrivacyInfo.xcprivacy` | the privacy manifest (§4) | - |
| `embedded.provisionprofile` | the operator's MAS profile, added at signing | - |

The vault, the socket and the state directory are in `~/Library/Group Containers/<TEAMID>.credmgr/` (`vault/`,
`vault/run/broker.sock`, `state/`).

---

## 2. Listing drafts

Limits are App Store Connect's: name and subtitle 30 characters, promotional text 170, keywords 100 bytes,
description 4000.

**Name** (28): `CredMgr – Vault for AI Agents`
Alternatives: `CredMgr: Local Secrets Vault` (28), `CredMgr` (7, if the name alone is wanted).

**Subtitle** (29): `Keys for your agents, offline`
Alternative: `Local vault for API keys` (24).

**Promotional text** (164):
> Give coding agents the credentials they need and nothing more. CredMgr keeps your API keys in an encrypted
> vault on this Mac and hands each agent only what you allow.

**Description** (draft, about 1,900 characters):

> CredMgr is a credential vault for people who work with AI coding agents. Your API keys, tokens and passwords
> stay encrypted on this Mac. Agents ask CredMgr for what they need, and you decide what each one may see.
>
> ORGANISE BY PROJECT
> Group secrets into nodes, one per project or client. Bind a folder to a node, and an agent working in that
> folder sees that node's entries and nothing else.
>
> AGENTS USE KEYS WITHOUT READING THEM
> CredMgr speaks the Model Context Protocol, so agents such as Claude Code, Claude Desktop, Cursor and others
> can look up and use credentials through it. Choose per node whether agents may read values, only use them, or
> nothing at all. Sensitive requests wait for your approval.
>
> YOUR MAC, YOUR KEYS
> No account, no cloud, no sync server, no telemetry. CredMgr makes no network connection at all. The vault is
> sealed with your passphrase (Argon2id) and each project's entries with their own key. Touch ID can confirm
> sensitive actions and unlock the vault.
>
> SEE WHAT HAPPENED
> Every decision is written to a tamper-evident audit log you can read in the app or from the command line.
>
> FOR THE TERMINAL TOO
> The app includes the credmgr command-line tool for listing, reading and adding entries and for running the
> MCP server. In this App Store edition it runs inside the macOS sandbox: it reads files you pipe to it rather
> than paths you name. A full command-line edition is available separately for free.
>
> STAY AVAILABLE WHEN THE WINDOW IS CLOSED
> Optionally let CredMgr keep its background service running so your agents and the command line can reach the
> vault after you close the window. It is off until you turn it on, and you can switch it off in System
> Settings › General › Login Items at any time.
>
> CredMgr is source-available. Security fixes are always free.

Before publishing: remove any client name the operator does not want to name, check the "free full CLI" line
against what is actually published, and keep the description in step with `PRIVACY.md` and the About screen.

**Keywords** (97 bytes, no spaces after commas, no words already in the name):
`api keys,secrets,password manager,mcp,claude,cursor,developer,tokens,env,touch id,keychain,encrypt`
Check trademark use of third-party names (claude, cursor) with counsel before submitting; drop them if in doubt.

**Category.** Primary: **Developer Tools** (`public.app-category.developer-tools`, written into Info.plist by
the build). Secondary: **Utilities**. (Productivity is the alternative secondary.)

**Support URL / marketing URL / privacy policy URL**: operator to supply (a page on the FreeXStudio site for each;
the privacy policy page carries `PRIVACY.md`, updated for the MAS paths and for StoreKit when S2 lands).

**Copyright**: `© 2026 FreeXStudio` (operator to confirm the legal entity name).

---

## 3. Age rating answers

App Store Connect's questionnaire, answered for the app as it is:

| Question group | Answer |
|---|---|
| Cartoon or fantasy violence; realistic violence; prolonged graphic violence | None (the built-in CredPong game is a paddle-and-ball game with no violence) |
| Sexual content or nudity; graphic sexual content | None |
| Profanity or crude humour | None |
| Alcohol, tobacco or drug use or references | None |
| Mature or suggestive themes; horror or fear themes | None |
| Medical or treatment information | None |
| Simulated gambling; contests | None |
| Unrestricted web access | **No** (no browser; the window loads only its own bundled pages, CSP `default-src 'self'`) |
| User-generated content shared with others; messaging or chat | No |
| Parental controls; age assurance | No |
| Advertising | No |

Expected rating: **4+**.

---

## 4. Privacy: the "nutrition label" and the manifest

**App Privacy answer: Data Not Collected.** CredMgr collects no data: nothing leaves the Mac, there is no
analytics, crash reporter, advertising identifier or account, and the broker has no network entitlement. Every
category (contact info, health, financial, location, sensitive info, contacts, user content, browsing and search
history, identifiers, purchases, usage data, diagnostics, other) is answered "not collected". When the StoreKit
purchase lands (phase S2), purchases are handled by Apple and still not collected by the developer; re-answer the
questionnaire then.

**Privacy manifest** (`packaging/mas/PrivacyInfo.xcprivacy`):

| Key | Value | Why |
|---|---|---|
| `NSPrivacyTracking` | false | no tracking of any kind |
| `NSPrivacyTrackingDomains` | empty | no network |
| `NSPrivacyCollectedDataTypes` | empty | nothing collected |
| File timestamp APIs | `C617.1` | Rust's `std::fs` metadata calls (`stat`, `fstat`, `lstat`) on vault, state and backup files, all inside the app-group container |
| System boot time APIs | `35F9.1` | elapsed time for auto-lock, rate limits and the unlock back-off (`std::time::Instant`); declared because the clock call may resolve to `mach_absolute_time` |
| Disk space, UserDefaults, active keyboards | not declared | not used: no `statfs`/volume-capacity query; preferences live in the webview's own storage; WebKit is a system framework and exempt |

Checked by grepping the workspace, the shell and the Swift helper on 2026-11-14 (no `NSUserDefaults`,
`statfs`/`statvfs`, `systemUptime` or `mach_absolute_time` in our code or in `tao`/`wry`/`tauri-runtime-wry`/
`muda`/`tray-icon` sources). **Confirm with Xcode's privacy report** (Organizer › Generate Privacy Report) on the
first real archive; App Store Connect warns on a missing declaration at upload.

---

## 5. Screenshots

Apple takes 1 to 10 Mac screenshots, 16:10, in one of **1280×800, 1440×900, 2560×1600 or 2880×1800** pixels (use
2880×1800 from a Retina Mac; the window is 1280×820 by default, so capture the window on a plain background at
that size). An app preview video (15 to 30 seconds) is optional.

Use a **demo vault with invented data only** (names like `acme-billing`, `sk-demo-...` values that are visibly
fake). Never a real key, never a real client name.

| # | Screen (source file) | What it shows | Caption draft |
|---|---|---|---|
| 1 | Main graph (`S1-main.html`) | nodes per project with their entries | Every project's keys, in one place |
| 2 | Entry inspector (`S4-inspector.html`) | an entry's fields, expiry chip, History tab | Fields, expiry and history for each key |
| 3 | Agents (`S21-agents.html`) and `dlg-agent.html` | an agent request waiting for approval | Agents ask; you decide |
| 4 | Grant (`S11-grant.html`) | node access for agents: read, use only, none | Agents can use a key without reading it |
| 5 | Settings › Security (`S12-settings.html`) | security level, Touch ID, Start at login | Touch ID and a background service you control |
| 6 | Lock screen (`S16-lock.html`) | the locked vault | Locked until you say so |
| 7 | Audit (`S14-ops.html`) | recent decisions | A tamper-evident record of every decision |
| 8 | Terminal beside the app (optional) | `credmgr list` and an MCP client using it | Works from the command line too |

---

## 6. Notes for App Review

To paste into "App Review Information › Notes" (edit the bracketed parts):

> CredMgr is a local, offline credential vault. It has no account and no server: there is nothing to log in to.
>
> To test: open the app, choose Create vault and set any passphrase (for example "review-passphrase-2026"). Add a
> node and an entry with a made-up value. Everything is stored in the app group container on this Mac.
>
> Background service: CredMgr includes a helper (credmgrd) that holds the unlocked vault so the bundled
> command-line tool and AI coding agents (via the Model Context Protocol) can reach it. It is registered with
> SMAppService only when the user turns on Settings > Security > Start at login, which is off by default. It
> then appears in System Settings > General > Login Items, where it can be switched off. It runs sandboxed in the
> same app group, has no network entitlement, and stops when unregistered.
>
> Command-line tool: Contents/MacOS/credmgr. Try:
> /Applications/CredMgr.app/Contents/MacOS/credmgr status
> It is sandboxed and refuses commands that would open a file path outside its container, with an explanation.
>
> Network: the app makes no network connections and requests no network entitlement. Touch ID is optional and
> uses a non-permanent Secure Enclave key (no keychain entitlement).
>
> [When the StoreKit purchase lands: the purchases and how to test them in the sandbox environment.]

Also tick "Sign-in required: No". No demo account is needed.

---

## 7. Export compliance

**Answer: `ITSAppUsesNonExemptEncryption = true`** (written into the MAS Info.plist by `release-app.sh --mas`).

Why:
- Apple's rule: set the key to `NO` only if the app uses no encryption or only forms exempt from the documentation
  requirements; using the encryption built into the operating system is typically exempt, proprietary encryption
  is not ([Complying with Encryption Export Regulations](https://developer.apple.com/tutorials/data/documentation/security/complying-with-encryption-export-regulations.md)).
- CredMgr does not call Apple's crypto for its vault. It implements **standard** algorithms itself, from audited
  Rust crates: XChaCha20-Poly1305, X25519, Argon2id, HKDF/HMAC-SHA256, ECDSA P-256. Apple's table for "industry
  standard algorithm, not provided within the Apple operating system" requires one document: the **French
  encryption declaration, only if the app is distributed in France** ([Export compliance documentation for
  encryption](https://developer.apple.com/help/app-store-connect/reference/export-compliance-documentation-for-encryption)).
  No CCATS is needed (that is for proprietary algorithms).
- Its primary function is information security, so the EAR Category 5 Part 2 Note 4 carve-out (for items whose
  primary function is not security) does not apply. Under US export rules it is a mass-market encryption item
  (5D992.c, License Exception ENC §740.17(b)(1)). Since March 2021 BIS no longer requires the annual
  self-classification report for most mass-market end items ([Thompson Hine summary](https://www.thompsonhine.com/publications/bis-eliminates-most-mass-market-encryption-reporting-obligations)),
  and Apple notes the report is unnecessary when documentation is given to Apple. **Counsel to confirm** the
  classification and France before the first submission.

In App Store Connect's questionnaire: uses encryption → yes; algorithm type → standard algorithms instead of, or
in addition to, Apple's; available in France → the operator's choice (if yes, upload the French declaration).
If Apple then issues a compliance code, add it as `ITSEncryptionExportComplianceCode` (one line in
`rl_mas_assemble`).

---

## 8. Guideline map

| Guideline | How the MAS edition meets it |
|---|---|
| 2.4.5(i) sandboxed | every executable carries `app-sandbox` (inspected) |
| 2.4.5(ii) self-contained, nothing in shared locations | CLI bundled, agent plist in the bundle, data in the group container; nothing in `/usr/local` |
| 2.4.5(iii) consent before running at login or after quit | the agent registers only on the user's Start at login click; Login Items shows it |
| 2.4.5(iv) no downloading code or apps | the full CLI is a separate download the app never fetches |
| 2.4.5(vi) no licence-key screens or own copy protection | none in the MAS build; **the ADR-082 supporter code field must be hidden first (open)** |
| 2.4.5(vii) updates only through the store | no updater exists; inspection refuses updater keys |
| 3.1.1 no unlocking with codes or crypto | **open:** hide the supporter code and the crypto donation addresses in the MAS flavour; a StoreKit Supporter purchase replaces them (S2) |
| 5.1.1 privacy | Data Not Collected; manifest in the bundle |

---

## 9. Operator-only steps (what blocks a submission)

In order. None of these can be done from the repository.

1. **Decide** the final bundle id and the app-group name (plan §9 decision 4), and whether to ship both editions
   (decision 4, recommended). Then edit `packaging/mas/identity.conf`: `MAS_TEAM_ID`, `MAS_BUNDLE_ID` if it
   changes, `MAS_IDS_FINAL=yes`.
2. **Apple Developer Program**: enrol or confirm the membership (organisation account, the FreeXStudio legal entity),
   accept the latest agreements, and complete the Paid Applications agreement, tax and banking (needed for any
   in-app purchase).
3. **Identifiers** (Certificates, Identifiers & Profiles): register the App ID with the final bundle id; register
   the app group `<TEAMID>.<name>` and enable App Groups on the App ID. Decide whether the helpers need their own
   App IDs (`<bundle>.brokerd`, `<bundle>.cli`); register them if the profile check at upload asks.
4. **Certificates**: "Apple Distribution" (or "3rd Party Mac Developer Application") and "3rd Party Mac Developer
   Installer"; plus "Apple Development" and a development profile for local sandbox testing.
5. **Provisioning profile**: a Mac App Store distribution profile for the App ID (with the app group), downloaded
   for `sign-notarise.sh --mas --profile-file`.
6. **App Store Connect record**: create the macOS app with the bundle id, SKU, primary language; fill §2 (name,
   subtitle, description, keywords, URLs, category), §3 (age rating), §4 (App Privacy), §7 (export compliance),
   pricing (free, with the in-app purchases of S2 later) and availability. Decide on family sharing for purchases
   before creating any (plan §9 decision 5: it cannot be turned off).
7. **Legal**: counsel review of the licence text and EULA (plan §9 decision 7; Apple's standard EULA or a custom one
   with Apple's minimum terms), the export classification and France (§7), and third-party names in keywords.
8. **On a Mac**: run `scripts/release-app.sh --mas`, fix whatever the first real build finds, then remove the
   dry-run guard in `sign-notarise.sh --mas` in the change that first runs it, sign, and check with
   `codesign -d --entitlements -` that each executable carries its entitlements.
9. **Spikes before TestFlight** (§10): the sandboxed agent registers and starts; the app, the agent, the CLI and an
   MCP client started by Claude Desktop all reach the socket in the group container; Touch ID through the inherit
   helper.
10. **TestFlight**: upload the `.pkg` with Transporter, test internally on at least two Macs (macOS 13 and the
    current release), including a user name of about 20 characters (socket path).
11. **Submit for review** with §6's notes. Expect questions about the background agent.

Code still to do before the first submission (not operator steps, but blocking): hide the supporter code and
donation addresses in the MAS flavour; a save/open panel for backup and restore (and the vault move between
editions, ADR-112); the self-integrity check accepting Apple's re-signature once it exists (doc 21 §3).

---

## 10. The riskiest unknowns

1. **Will App Review accept a sandboxed `SMAppService` agent that holds an unlocked vault?** Not documented either
   way. Apple's support engineers say a sandboxed app's agent must itself be sandboxed (enforced since macOS 14.2),
   which ADR-162 does. The consent and Login Items visibility answer 2.4.5(iii). Risk: **medium-high**. Fallback,
   already designed: the broker as a child of the app plus `SMAppService.mainApp` (ADR-162). Ask early with a
   TestFlight build and, if needed, an App Review appointment.
2. **A Unix socket between separately sandboxed processes in one app group.** Apple's documentation places shared
   IPC files in the group container, and a group member may create and connect to a socket there; this is the
   documented pattern, but CredMgr has not run it. The peer gate (uid) is unaffected; the advisory pid→cwd lookup
   may be refused across sandboxes, which makes folder-bound scoping fall back to "no match" (never to "allowed").
   An MCP client app that is itself sandboxed would start our CLI inheriting nothing, which is fine. Risk:
   **medium**, cheap to settle on a Mac in a day.
3. **StoreKit without `network.client`.** StoreKit talks to a system daemon, so the app should not need a network
   entitlement; believed, not verified (memo 04). If it does need one, it goes on the app only, never on the broker,
   with its own ADR. Risk: **low-medium**; phase S2's spike settles it.
4. **The sandbox CLI's usefulness.** Losing file paths, export and agent wiring may make the bundled CLI feel
   broken to the developer audience; the listing and the refusal messages say so and point to the full CLI.
   Product risk, not a review risk.
5. **The `SMAppService` code itself** was written against the documented API and compiled only for Linux (where
   it is excluded); the first macOS build may need small fixes.
