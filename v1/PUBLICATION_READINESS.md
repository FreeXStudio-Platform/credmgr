# CredMgr V1 publication readiness

Reviewed: 2026-10-01. Scope: `v1/` only. V2 is excluded from this work.

The reviewed V1 patch is **1.9.1**. Remote main was **1.9.0** at the start of this review. No repository tags or
GitHub Releases existed at this check. The repository is private. Do not
describe the source version as a published signed release.

## Verified

- Node.js 24.19.0 and age 1.2.1 on Linux.
- `npm test`: 230 passed, zero failed, in a disposable vault. The suite includes
  regression tests observed failing before the repairs and bounded stress checks.
- The V1 working-tree secret guard passed.
- Nested and standalone hooks were exercised by real commits in disposable Git
  repositories. Staged-only secrets, deleted/sanitized working files, unusual
  pathnames, binary bytes, escaped symlink directories, and oversized files were
  checked. `--all` stayed inside the package when called from its parent repo.
- A high-confidence pattern scan of 58 reachable historical V1 blobs found
  no matching credential patterns. It does not establish whole-repository or
  complete history clearance; V2 was excluded.
- `npm audit --omit=dev --audit-level=high`: zero reported vulnerabilities.
- Focused V1 HTTP/PIN/bearer, MCP, path, and age integration review repaired route
  spelling/HEAD gate bypasses, default-loopback DNS rebinding, stale PIN sessions,
  malformed configuration/registry fail-open behavior, and symlinked vault homes.
  This was a focused source-backed review, not an exhaustive security audit.
- Saved-token rotation/revocation was tested against the running HTTP app and
  real CLI daemon. Explicit flag/environment-token behavior stayed fixed. The
  library environment-object helper was tested with plaintext, empty values,
  and a prototype-shaped credential name.
- Bounded stress used 256 staged files, 256 KiB binary encryption plus 16
  ciphertext alterations, 256 dry-run import records, 64 actual Unicode records,
  and 64 concurrent locked GET/HEAD requests. All inputs were disposable.
- Native macOS shell builds and interactive desktop behavior remain untested
  in this run. Linux checks do not establish macOS or Windows readiness.

Protected `.git` markers in the cloud machine's `/tmp` and `/workspace`
correctly prevent vault initialization there. Tests used a mode-0700 private
temporary directory outside Git. Keep the safeguard enabled.

## Publication gates

1. Choose a **V1-only publication target**. This repository also contains V2,
   which is excluded from review. Changing the entire repository to public
   would expose V2 and reachable history; a V1-only scan does not authorize it.
2. Review the exact public tree, history, commit metadata, and artifacts for
   credentials and personal material. A pattern scan is supporting evidence,
   not a guarantee. Keep real vaults and exports outside the checkout.
3. Confirm installation, license, trademarks, acknowledgements, privacy, and
   the private security-reporting channel against the chosen target.
   The repaired installer and staged-byte guard are tested in both nested and
   standalone layouts. Retest the exact publication artifact in a fresh local
   Git repository; working-tree clearance does not clear staged bytes or history.
4. Test any distributed native shell on supported operating systems. Exercise
   clean install, lock/unlock, reveal/copy, import/export, backup/restore, and MCP
   with disposable data.
5. Produce a versioned artifact and checksum, test that exact artifact, and
   publish release notes. Claim signing only with verified signing evidence.
6. Keep `package.json` private until npm publication is intentionally chosen.
   Public GitHub source does not require npm publication.

## Prepared V1-only source package

The release preparation uses `git archive <reviewed-commit>:v1` to create a
versioned V1 source tree with its own license, documentation, lockfile, runtime,
tests, and native macOS source. The archive contains no parent repository files,
V2 files, vaults, dependencies, or Git history. Its checksum and exact source
commit/tree are recorded beside the artifact. Extracting it is source delivery,
not a signed binary, npm publication, or authorization to publish the shared repo.

For an archive check, initialize a fresh local Git repository in the extracted
package, run `npm ci`, and run the guard and full suite with a private disposable
test directory outside Git. A public target and native operating-system checks
remain publication gates.

## Cloud-assistant access

Stdio MCP runs on the same machine as its client. It does not give a cloud
assistant remote access to a vault on your laptop. Use a separate vault with a
trusted local MCP client, or enter narrowly scoped credentials through secure
cloud environment settings. Never expose the V1 HTTP daemon publicly or paste
secrets into chat. Read-only MCP mode limits writes, not the values it can read.
