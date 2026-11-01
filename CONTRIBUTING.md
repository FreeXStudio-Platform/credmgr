# Contributing

Thank you for considering it. This is a credential vault, so the bar is deliberately higher than
for most projects — please read §1 before writing code.

This repository holds two products. This file covers what applies to both and tells you where
the rest lives:

| Working on | Read next |
|---|---|
| **V2** — Rust: `credmgr`, `credmgrd`, the MCP server, the desktop bridge (`v2/`) | [`v2/CONTRIBUTING.md`](v2/CONTRIBUTING.md) |
| **V1** — the legacy Node.js line (`v1/`) | [`v1/CONTRIBUTING.md`](v1/CONTRIBUTING.md) |

New features belong in V2. V1 takes fixes.

## 1. The rules that are not negotiable

1. **Never commit a credential.** Run the guards before you commit, and put them in a
   pre-commit hook so you cannot forget. Both guards scan the whole staged diff, so one hook
   covers V1 and V2 changes alike:
   ```bash
   node v2/scripts/guard-no-secrets.mjs           # staged changes; add --all for the whole tree
   node v2/scripts/guard-no-personal-data.mjs     # same, for home paths, e-mail addresses, IPs

   # install both as the pre-commit hook (from anywhere inside the clone)
   hook="$(git rev-parse --git-path hooks/pre-commit)"
   printf '%s\n' \
     '#!/bin/sh' \
     'ROOT="$(git rev-parse --show-toplevel)" || exit 1' \
     'node "$ROOT/v2/scripts/guard-no-secrets.mjs" || exit 1' \
     'node "$ROOT/v2/scripts/guard-no-personal-data.mjs" || exit 1' > "$hook"
   chmod +x "$hook"
   ```
   The snippet replaces any pre-commit hook you already have; if you have one, append the two
   `node` lines to it instead. Do **not** use `guard-no-secrets.mjs --install` in this
   repository: it writes a hook that points at a top-level `scripts/` directory, which this
   repository does not have, so every commit would then fail with "Cannot find module".
   (V1 has its own installer, `npm run hooks:install` inside `v1/`; it guards `v1/` only.)
   There is no `--force`. If a guard fires on something genuinely safe, add a `credmgr-allow`
   comment on that line, or within the five lines above it, **explaining why**, and say so in
   the PR. On every pull request CI runs the personal-data guard over the whole tree, the secret
   guard over `v1/`, and Semgrep's secret-detection rules over everything.

2. **Never use a real credential in a test or a fixture.** Generate throwaway values. Tests run
   against a disposable vault; they must never touch a real one.

3. **Never put your own machine in the repository** — no home-directory paths, host names, IP
   addresses, e-mail addresses, project names or server names of yours. The personal-data guard
   checks for the shapes of these.

4. **Do not weaken a gate to make a test pass.** If a test is hard because the security model is
   in the way, that is the security model working. Say so in the issue.

5. **Do not add a network call to the vault process, and do not add telemetry.** The V2 broker has
   no network client by construction and its dependency policy makes adding one a build failure;
   the privacy policy rests on it.

6. **New MCP tools need a design discussion first.** Some tools must never exist — grant creation,
   orphan reads, 2FA-seed retrieval, self-permission changes, audit purging. A test enumerates
   the live tool registry and fails if one appears.

## 2. Getting set up

```bash
git clone https://github.com/FreeXStudio-Platform/credmgr.git && cd credmgr
```

Cloning the repository, or forking it on GitHub, is allowed only to read it or to prepare a
contribution ([`LICENSE`](LICENSE) §2); a fork may not be run, published or distributed.

- **V2:** install Rust through `rustup` (the workspace pins its toolchain in
  `v2/rust-toolchain.toml`), then follow [`v2/CONTRIBUTING.md`](v2/CONTRIBUTING.md). The desktop
  shell in `v2/apps/desktop/src-tauri` is a separate Cargo workspace with its own pin
  (ADR-035 in [`v2/docs/14_DECISIONS.md`](v2/docs/14_DECISIONS.md)).
- **V1:** `cd v1 && npm ci`, then follow [`v1/CONTRIBUTING.md`](v1/CONTRIBUTING.md).
- **Documentation:** the design corpus is in [`v2/docs/`](v2/docs/00_README_START_HERE.md). Run
  `python3 -m tools.corpus_check` from the repository root after editing it; it cross-checks the
  docs against the code.

## 3. Before you open a PR

For V2 changes:

- [ ] `cargo test --workspace` (run inside `v2/`) is green, and you added tests for what you
      changed. The suite uses real sockets and Argon2id key derivation, so it takes a long time;
      that is expected, not a hang. The desktop bridge has its own suite: `cargo test` inside
      `v2/apps/desktop/src-tauri`; the desktop front end has its own gates inside `v2/apps/desktop`
      (`npm test`, `npm run test:csp`, `npm run test:e2e`, `npm run test:design`; see
      [`v2/CONTRIBUTING.md`](v2/CONTRIBUTING.md)).
- [ ] `cargo clippy --workspace -- -D warnings` and `cargo fmt --all -- --check` are clean
- [ ] `cargo deny check` is clean, and any new dependency is explained in the PR description
- [ ] `python3 -m tools.corpus_check` exits 0 if you touched `v2/docs/`

For V1 changes: `npm test` and `npm run guard`, both inside `v1/`.

For every change:

- [ ] Both secret guards in §1 are clean
- [ ] `CHANGELOG.md` (of the product you changed) is updated under `[Unreleased]`
- [ ] Docs are updated if you changed behaviour anyone relies on

## 4. What makes a PR easy to merge

- **One thing.** A focused change is reviewed in an hour; a mixed one waits weeks.
- **A failing test first**, then the fix.
- **Say what you did NOT do**, and why. That sentence saves the most review time of anything you
  can write — the pull-request template asks for it.
- Match the surrounding style. There is no linter religion here; there is consistency.
- Comments explain **why**, never what. The code says what.

## 5. What is likely to be declined

- Cloud sync, hosted backup, a web version, an account system. CredMgr is local-only and that is
  the product, not a missing feature.
- Telemetry or analytics, in any form, however anonymous.
- A plugin system for the vault process. Nothing outside may load inside.
- A new cipher, or a cipher-suite selector.
- Anything that makes a secret easier to display than to copy.
- Large refactors without a prior issue. Not because they are unwelcome — because a rewrite
  nobody agreed on is a rewrite nobody can review.

## 6. Reporting bugs

Ordinary bugs: open an issue and fill in the template — product (V1 or V2), version, OS, what
you did, what happened, what you expected. Get the version with `credmgr --version` (V2). V1 has
no `--version` flag: run `node -p "require('./package.json').version"` inside your `v1/`
checkout. Do not paste the output of `credmgr which` — it prints your home directory, and issues
are public. **Security bugs: do not open an issue** — follow [`SECURITY.md`](SECURITY.md).

## 7. Licence

Contributions are made under section 4 of [`LICENSE`](LICENSE): you confirm that you wrote your
contribution or have the right to share it, and you grant FreexStudio a perpetual, worldwide,
irrevocable, royalty-free licence to use, modify, publish and distribute it as part of CredMgr,
under any terms FreexStudio chooses. You keep your own copyright. You receive no payment and no
ownership of the software.

Everyone taking part is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).
