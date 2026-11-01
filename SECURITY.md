# Security policy

CredMgr holds passwords, private keys and recovery phrases. Security reports are the most
valuable contribution anyone can make to this project, and they are treated that way.

This repository contains two products, each with its own detailed policy. This file is the front
door: it tells you how to report, and which policy applies to what you found.

## Reporting a vulnerability

**Do not open a public issue for a security bug.**

1. **Use GitHub's private vulnerability reporting**: the repository's *Security* tab →
   *Report a vulnerability* (or open
   [a new advisory](https://github.com/FreeXStudio-Platform/credmgr/security/advisories/new) directly).
   That gives you a private thread with the maintainers and, if you want it, a CVE and public
   credit when the fix ships.
2. If that is unavailable to you, open a public issue containing only the words
   *"security report, please open a private channel"* and nothing else. No details.

**What to include:** what you found · how to reproduce it · what an attacker gains · the
version and OS · anything you think we will get wrong when we try to fix it.

**Never include a real credential in a report** — no vault, export, master key, recovery code or
token. Reproduce with a disposable vault. If you believe you have found a way to read someone
else's data, say so in words; do not attach it.

There is no bug bounty. This is a small project, and that is stated up front rather than implied.

## Which policy applies

| You found it in | Policy |
|---|---|
| **V2** — the Rust rewrite: `credmgr`, `credmgrd`, the MCP server, the desktop bridge (everything under [`v2/`](v2/)) | [`v2/SECURITY.md`](v2/SECURITY.md) — scope, what is out of scope, response targets, our commitments |
| **V1** — the legacy Node.js line: the CLI, dashboard, SDK and MCP server (everything under [`v1/`](v1/)) | [`v1/SECURITY.md`](v1/SECURITY.md) — V1's boundaries and limits |
| Not sure | Report it anyway and say what you ran. It will be routed. |

The two products have different security models — V1's "projects" are filters, V2's nodes are
cryptographic boundaries — so the same symptom can be a defect in one and a documented limit in
the other. Each policy file says which is which. Please read the relevant one before reporting;
it also saves you from writing up something that is documented behaviour.

## Supported versions

- **V2** is pre-release. Only the newest V2 build gets security fixes; an older pre-release is
  not patched. Its version is printed by `credmgr --version`.
- **V1** (`1.x`) is the legacy line: it takes fixes, and new development is in V2. Its version is
  in [`v1/package.json`](v1/package.json).

No GitHub release has been published yet. [`v2/SECURITY.md`](v2/SECURITY.md) and
[`v1/SECURITY.md`](v1/SECURITY.md) carry the detail for each line.

**If you ran a V2 alpha build** (`2.0.0-alpha.4` to `2.0.0-alpha.6`), read
[`v2/SECURITY.md`](v2/SECURITY.md), "Session token in the audit log" — those
builds recorded each login's token in the plaintext audit log. It is fixed in this tree, and the
page says what an existing vault still holds and what to do.

## Documented limits are not defects

Both products state plainly what they do not defend against. The headline one: an attacker with
code execution as **your own user account** on an **unlocked** vault is out of scope. No
user-space vault defends against that, and claiming otherwise would be dishonest. The V2 threat
model is [`v2/docs/05_THREAT_MODEL.md`](v2/docs/05_THREAT_MODEL.md); the build's known risks
(K-1 … K-10) are recorded in [`v2/docs/PHASE8_AUDIT_REPORT.md`](v2/docs/PHASE8_AUDIT_REPORT.md) §4
and in [`v2/RELEASE.md`](v2/RELEASE.md). Reporting a known risk is welcome if you can show it is
worse than it is described.

**What V2's Software tier does and does not protect** (the same wording is in
[`v2/SECURITY.md`](v2/SECURITY.md)): your passphrase is the key — a copy of the vault folder can be attacked
offline on any computer, slowed only by Argon2id (256 MiB, 3 passes, 4 lanes) per guess, and nothing is held in
the Mac's Secure Enclave; while the vault is unlocked, `credmgrd` holds the root key and every unlocked project
key in memory and does not lock its pages or block debuggers; there is no Touch ID or presence check, so
presence-gated operations are refused; and **two-factor guards the door, not the safe** — `credmgrd` enforces
it, the encryption does not, so someone with your passphrase or recovery code and a copy of the vault folder
can decrypt without the second factor.

## If you think your vault is compromised

1. Lock the vault if you can (V2: `credmgr lock`), and stop any broker, daemon or integration
   that is running.
2. Rotate credentials at their issuing services, in this order: anything that moves money
   (wallets, exchange keys, payment providers) · cloud and server root access · CI/CD and deploy
   tokens · everything else.
3. Review the audit trail for what was read, and when. Do **not** delete it — a break in its hash
   chain is itself evidence.

## Our commitments

- **No telemetry, ever** — no analytics, no crash reporting, no usage statistics, no update ping.
- **No network client in the V2 broker.** The broker, the process that holds V2's keys, has none,
  and the dependency policy ([`v2/deny.toml`](v2/deny.toml)) makes adding one a build failure. V1
  is a different design: it serves a local dashboard on loopback and has explicit commands that
  may contact a server you choose, as [`v1/PRIVACY.md`](v1/PRIVACY.md) spells out.
- **Security fixes ship before features**, and the changelog says plainly what was wrong.

Release builds and the desktop app are **not code-signed or notarised yet**; the `SHA256SUMS` file that
accompanies a build is its only provenance. That is stated in [`v2/RELEASE.md`](v2/RELEASE.md) rather than left
for you to discover. A vault that a 2.0.0-beta.1 build has written to cannot be opened by an alpha build.
