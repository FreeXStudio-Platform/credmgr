# CredMgr V1 privacy policy

Updated: 2026-10-01. Applies to the V1 CLI, local dashboard, SDK, MCP server,
and optional macOS shell in this directory.

V1 has no hosted account, telemetry, analytics, advertising identifier, or
crash-reporting endpoint. The dashboard uses a local loopback HTTP server.
Do not expose a credential daemon to the public Internet.

## Local storage

The vault lives outside the checkout in your platform's user-data directory.
Run `credmgr where` to locate it.

| Data | Storage |
|---|---|
| Credential values | Encrypted with age in `store/vault.age` |
| Names, projects, categories, descriptions, tags | Plaintext `store/index.json` |
| Decryption identity | Local `.credmgr/master.key`, optionally machine-locked |
| Change history | Encrypted files under `.credmgr/changelog/` |
| Access records and settings | Local plaintext files |

V1 uses one vault identity, not a separate key per project. Do not put sensitive
values in metadata. Machine-lock uses the machine's OS identity; it is not a
hardware keystore. Protect your account, disk, identity material, and backups.

## Network and integrations

The dashboard serves local HTTP requests with bundled assets. MCP uses standard
input/output; the SDK's HTTP client can contact a configured credential daemon.
Explicit transfer/deploy commands may contact a user-selected server. V1 has
no automatic update check or telemetry service. Opening documentation in your
browser may contact that external site.

The integration flow stores a local integration record and provides a
configuration snippet for you to copy into a client manually. It does not
automatically edit or back up that client's configuration. Those clients have
their own privacy policies.

## AI-client access

An authorized V1 MCP client can read values throughout the vault. Project names
are filters, not authorization boundaries. Write tools are enabled by default;
`--read-only` disables writes but does not limit value reads to one project.
The dashboard PIN does not restrict a local CLI or MCP process running as the
same operating-system user with access to the vault identity.

Returned values enter the client's context and may reach its provider. Use a
separate vault containing only credentials needed by that integration. Local
access records do not prove that a recipient kept a value private or deleted it.

## Export, clipboard, backup, and deletion

An explicit export, reveal, or clipboard operation exposes plaintext to its
destination. Protect exported files and backups separately. Encrypted backups
also require protection for the identity material used to decrypt them.

You can locate, export, back up, and remove your local data. FreexStudio holds
no hosted vault copy. Values sent to an AI provider are subject to its retention
and deletion controls.

## Reports and policy changes

Never attach real credentials, identities, exports, or personal access logs to
an issue. Follow [SECURITY.md](SECURITY.md) for sensitive reports. Policy changes
are recorded in [CHANGELOG.md](CHANGELOG.md).
