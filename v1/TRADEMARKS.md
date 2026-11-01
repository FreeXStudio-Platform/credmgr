# Trademark and brand policy

The **source code** of CredMgr is source-available under the FreexStudio Source-Available Licence —
see [LICENSE](LICENSE). The code is public to be read and audited; it is not licensed for copying,
forking, modification or redistribution.

The **names and brand assets are separate** from the code and are reserved:

- **CredMgr** — the product name
- **FreexStudio** — the publisher name
- the CredMgr mark, wordmark, icon and any visual identity shipped in `design/` or `assets/`

These remain the property of FreexStudio.

## What you may do without asking

- Use the name truthfully in articles, tutorials, reviews, comparisons and talks.
- Say accurately that your own tool *works with* CredMgr.
- Link to the project.

## What you may not do

Without written permission from FreexStudio (Admin@freexstudio.com):

- Package, mirror or redistribute CredMgr in any form, including for a distribution or package
  registry (Homebrew, AUR, apt, winget, nixpkgs), and call it CredMgr or anything else.
- Ship a modified or unofficial build called "CredMgr", or anything confusingly close.
- Use the CredMgr or FreexStudio marks as your own product, company, or app-store listing name.
- Imply endorsement, affiliation, partnership or official status.
- Use the marks on a paid product, a hosted service, or a token/coin.
- Alter the mark and present the result as CredMgr's identity.

The line is confusion. Describe your relationship to CredMgr accurately and you are fine;
make someone think your build *is* CredMgr and you are not.

## Why the name is protected

A credential vault is trusted software. If anyone could publish a modified build under this
name, a user could install a backdoored "CredMgr" and have no way to tell. **The name, together with
the licence's rule that only the official, unmodified release is approved for use, is what lets a
user know that the CredMgr they installed is the CredMgr that was audited.**

## Verifying an official build

An official release comes from the `github.com/FreeXStudio-Platform/credmgr` repository, on a tag,
with a `SHA256SUMS` file published beside it. Releases that also carry a detached signature and
platform code-signing say so in their release notes; the current `2.0.0-beta.1` is neither signed
nor notarised. If the checksums do not match, it is not an official build, whatever it is called.

## Questions

Write to **Admin@freexstudio.com**, or open a GitHub issue for a question that is not about a
permission.
