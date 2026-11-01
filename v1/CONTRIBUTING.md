# Contributing

Thank you for considering it. This is a credential vault, so the bar is deliberately higher
than for most projects — please read §1 before writing code.

## 1. The rules that are not negotiable

1. **Never commit a credential.** Scan the V1 tree before each commit:
   ```bash
   npm run guard
   ```
   There is no `--force`. If the guard fires on something genuinely safe, add a
   `credmgr-allow` comment on that line (or within the five lines above it) **explaining why**,
   and say so in the PR.

   Install or upgrade the staged-byte hook with `npm run hooks:install`. It
   supports this nested checkout and standalone V1. `npm run guard` scans the
   current V1 working files; the pre-commit hook independently checks Git's
   staged blobs and paths. Oversized or unreadable inputs fail closed.

2. **Never use a real credential in a test.** Generate throwaway values. Tests run against a
   sandboxed `CREDMGR_HOME`; they must never touch a real vault.

3. **Do not put secrets in argv, logs, metadata, or committed fixtures.** Read values
   through stdin where supported. V1 uses JavaScript strings internally and
   cannot promise that every secret copy is erased from memory.

4. **Do not weaken a gate to make a test pass.** If a test is hard because the security model
   is in the way, that is the security model working. Say so in the issue.

5. **New MCP tools need a design discussion first.** Review the actual V1 access
   boundary and MCP registry tests. Project filters are not access controls.

6. **Do not add a network call to the vault process.** It has none, by construction, and that
   is the property the privacy policy rests on.

7. **Do not hard-code your own projects, servers, or paths.** A previous version shipped one
   user's project inventory in `lib/classify.js`; user-specific rules belong in
   `<vault>/.credmgr/classify.rules.json`. There is a test guarding this too.

## 2. Getting set up

```bash
git clone https://github.com/FreeXStudio-Platform/credmgr.git
cd credmgr/v1
npm ci
npm run guard            # do this before each commit
npm run hooks:install    # install or upgrade the staged-byte hook
npm test                  # 229 checks; all must pass
node bin/credmgr where    # confirm your vault is OUTSIDE the repo
```

Cloning the repository, or forking it on GitHub, is allowed only to read it or to prepare a
contribution ([`LICENSE`](LICENSE) §2); a fork may not be run, published or distributed.

Node ≥ 18. `age` must be on PATH (`brew install age`, `apt install age`, `winget install age`).

On Codex cloud machines, protected `.git` markers may exist in `/tmp` and
`/workspace`. Set `TMPDIR` to an approved private directory outside Git before
running tests. Do not remove markers or bypass the vault-location safeguard.

## 3. Before you open a PR

- [ ] `npm test` — green, and you added tests for what you changed
- [ ] `npm run guard` — clean
- [ ] `credmgr verify` and `credmgr doctor` still pass on a scratch vault
- [ ] No new runtime dependency without saying why in the PR description
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Docs updated if you changed behaviour anyone relies on

## 4. What makes a PR easy to merge

- **One thing.** A focused change is reviewed in an hour; a mixed one waits weeks.
- **A failing test first**, then the fix.
- **Say what you did NOT do**, and why. That sentence saves the most review time of anything
  you can write.
- Match the surrounding style. There is no linter religion here; there is consistency.
- Comments explain **why**, never what. The code says what.

## 5. What is likely to be declined

- Cloud sync, hosted backup, a web version, an account system. CredMgr is local-only and that
  is the product, not a missing feature.
- Telemetry or analytics, in any form, however anonymous.
- A plugin system for the vault process. Nothing outside may load inside.
- A new cipher, or a cipher-suite selector.
- Anything that makes a secret easier to display than to copy.
- Large refactors without a prior issue. Not because they are unwelcome — because a rewrite
  nobody agreed on is a rewrite nobody can review.

## 6. Reporting bugs

Ordinary bugs: open an issue with your OS, the source version
(`node -p 'require("./package.json").version'` from `v1/`), what you did,
what happened, and what you expected. **Security bugs: do not open an issue** — follow
[SECURITY.md](SECURITY.md).

## 7. Licence

Contributions are made under section 4 of [`LICENSE`](LICENSE): you confirm that you wrote your
contribution or have the right to share it, and you grant FreexStudio a perpetual, worldwide,
irrevocable, royalty-free licence to use, modify, publish and distribute it as part of CredMgr,
under any terms FreexStudio chooses. You keep your own copyright. You receive no payment and no
ownership of the software.
