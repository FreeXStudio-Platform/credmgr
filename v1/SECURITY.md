# CredMgr V1 security policy

Never include a real credential, master key, vault export, or recovery material
in a report. Reproduce with a disposable vault.

## Private reporting

Use the repository's Security tab when private vulnerability reporting is
enabled. Otherwise, request a private reporting channel without posting details.
The repository is currently private; this document does not establish that
public reporting is configured.

Include the V1 source version, OS, reproduction steps, expected and actual
behavior, and impact. No response-time guarantee or bounty is established here.

## Version and release status

The current checked-in V1 package is **1.9.1**. Earlier documentation naming
1.8.x as the current version was stale. Use the latest reviewed V1 source and
[CHANGELOG.md](CHANGELOG.md). A package version is not evidence of a published,
signed release; see [PUBLICATION_READINESS.md](PUBLICATION_READINESS.md).

## V1 boundaries

- Values and change history are encrypted with age. Metadata is plaintext.
  Projects are filters, not encryption or authorization boundaries.
- The optional dashboard PIN gates specified value-revealing HTTP operations,
  rather than every interactive operation. Bearer-authenticated
  daemon clients bypass it by default unless configured otherwise. Local CLI
  and MCP processes using the same OS account can access the vault identity.
- MCP write tools are enabled by default. `--read-only` prevents MCP writes
  but does not limit value reads to a project.
- Dashboard and daemon bind to loopback by default. Exposing them to a network
  changes the threat model; do not publish a credential daemon as a web service.
- Default loopback HTTP servers require a loopback Host header to resist DNS
  rebinding. Bearer, PIN, and export-password comparisons cover Express's case
  variants, trailing slashes, and HEAD requests. Rotating a PIN revokes existing
  unlock sessions. Invalid security configuration or an invalid integration
  registry blocks the affected access instead of silently disabling its gate.
- Saved daemon tokens are checked on each request, so their rotation/revocation
  takes effect without restart. Explicit `--token` or `CREDMGR_TOKEN` overrides
  are fixed for that process and must be replaced or stopped separately.
- Machine-lock is OS-identity-based, not hardware-backed key isolation.
- JavaScript strings can retain secret copies. V1 does not guarantee complete
  memory erasure.
- The publication guard checks staged V1 blob bytes and paths; its working-tree
  mode stays within the V1 package. Pattern matches and explicit, justified
  line allowances cannot establish that all possible secrets are absent.

## In scope

Report unintended HTTP disclosure, failures of PIN or bearer authentication,
MCP read-only bypass, secret leakage in logs or metadata, unsafe path handling,
weaknesses in age integration or machine-lock, and accidental vault publication.

## Limits

V1 does not defend against code already running as your OS user, root/kernel
access, a debugger, or an authorized MCP client reading a value made available
to it. Presence-attested access, per-node keys, and project isolation are not
V1 features. A local access record is not a tamper-proof remote audit system.

## Suspected compromise

Stop affected daemons and clients, disconnect the integration, and rotate
credentials at their issuing services. Prioritize money-moving credentials,
cloud administration, and deployment access. Preserve redacted evidence and
access records. Locking the dashboard alone does not revoke a credential or
prevent local CLI access.
