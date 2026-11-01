# Contributing

Thank you for considering it. This is a credential vault, so the bar is deliberately higher
than for most projects — please read §1 before writing code.

## 1. The rules that are not negotiable

1. **Never commit a credential.** Two guards block it, `scripts/guard-no-secrets.mjs` and
   `scripts/guard-no-personal-data.mjs`; run both before every commit and install them as your
   pre-commit hook the way the repository's root [`CONTRIBUTING.md`](../CONTRIBUTING.md) §1 shows.
   Do **not** use `guard-no-secrets.mjs --install` in this repository (it is V1's installer and
   writes a hook that points at a directory this monorepo does not have). There is no `--force`.
   If a guard fires on something genuinely safe, add a `credmgr-allow` comment on that line (or
   within the five lines above it) **explaining why**, and say so in the PR.

2. **Never use a real credential in a test.** Generate throwaway values. Tests run against a
   throwaway vault directory (`CREDMGR_VAULT_DIR` and `CREDMGR_STATE_DIR` point into a temporary
   directory); they must never touch a real vault.

3. **A secret is never a string, an argv element, a log line, or an object key.** Pipe it,
   buffer it, wipe it.

4. **Do not weaken a gate to make a test pass.** If a test is hard because the security model
   is in the way, that is the security model working. Say so in the issue.

5. **New MCP tools need a design discussion first.** Some tools must never exist — grant
   creation, orphan reads, 2FA seed retrieval, self-permission changes, audit purging. There
   is a test that enumerates the live tool registry and fails if one appears.

6. **Do not add a network call to the vault process.** It has none, by construction, and that
   is the property the privacy policy rests on.

7. **Do not put your own machine in the repository** — no home-directory paths, host names, IP
   addresses, e-mail addresses, project names or server names of yours. V1 once shipped one user's
   project inventory in `lib/classify.js`; `scripts/guard-no-personal-data.mjs` now checks for the
   shapes of these on every commit and in CI.

## 2. Getting set up

**This is V2 — Rust, not Node.** (This section carried V1's `npm`-based setup verbatim until
2026-08-29; that repo lives at `v1/` in the same monorepo and has its own `CONTRIBUTING.md`.)

```bash
git clone <repo> && cd credmgr/v2
cargo build --workspace
cargo test --workspace     # about 800 tests in 50 binaries; all must pass. Real sockets and Argon2id KDF work: about
                            # ten minutes with a warm build even on a busy machine — not a hang.
```

Cloning the repository, or forking it on GitHub, is allowed only to read it or to prepare a
contribution ([`LICENSE`](LICENSE) §2); a fork may not be run, published or distributed.

Rust via `rustup`, MSRV 1.78 (`v2/rust-toolchain.toml` pins it) for `crates/`; the desktop app in
`apps/desktop` has its own workspace and pins its own, newer toolchain in
`apps/desktop/src-tauri/rust-toolchain.toml` (`ADR-035` — two pins, two lockfiles, deliberately).
`credmgr init` creates a real on-disk vault: build `credmgrd`, run it against an empty
`CREDMGR_VAULT_DIR`, then `credmgr init`; `credmgr unlock` against a running daemon opens that vault
from disk (ADR-063), so you can drive it end-to-end — `scripts/e2e-journey.sh` does exactly that
with the real binaries and is the check to run before trusting a change that touches the broker.
What is still genuinely open: the desktop app has not been walked by a person (`docs/RELEASE_VERIFICATION.md`) and
its real-broker suite fails its drift guard, presence cannot be
attested by any transport, and Windows/Linux hardware keystores don't exist
(`16_CROSS_PLATFORM.md §4`). The project's issue tracker holds the live, prioritized list.

## 3. Before you open a PR

- [ ] `cargo test --workspace` — green, and you added tests for what you changed
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` — clean
- [ ] `cargo fmt --all -- --check` — clean
- [ ] If you touched a broker op: `python3 scripts/endpoint-matrix.py` (every op over the real
      socket) and `scripts/e2e-journey.sh` (the real binaries) pass, and the op has a row in the
      matrix (`--check-coverage`)
- [ ] If you touched `apps/desktop`: `npm ci && npm run check && npm test && npm run build &&
      npm run test:csp && npm run test:e2e && npm run test:design` inside it, `npm run test:real` if you
      changed a bridge command, an argument or a broker op (it builds `credmgrd` and drives the built app
      against it), and `cargo test --locked` inside `src-tauri`
- [ ] If you touched a template under `apps/desktop/src/design/` or `docs/RELEASE_VERIFICATION.md`:
      `python3 -m tools.release_verification_check` from the repository root exits 0 (every control has a row)
- [ ] If you touched a release script: `scripts/release.sh --dev`, then `scripts/release-selftest.sh`
      (it must refuse every corrupted copy), and `scripts/fresh-install-check.sh`
- [ ] If you touched `docs/`: `python3 -m tools.corpus_check` from the repository root exits 0 (it
      counts ops and tools from the code), and the generated `.json` (and `.html`, where one is
      committed) beside the document is rebuilt:
      `python3 -m tools.docgen.cli build v2/docs/<file>.md -o v2/docs --formats json`
      (needs `pip install markdown pyyaml`, plus `npm ci` in `tools/visual-engine` for a document
      with a chart)
- [ ] `maintenance.verify`/`maintenance.doctor` still pass against a scratch vault, if your
      change touches on-disk state
- [ ] No new dependency without saying why in the PR description — `cargo deny check` runs in CI
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

Ordinary bugs: open an issue with your OS, the version (`credmgr --version`), what you did,
what happened, and what you expected. **Security bugs: do not open an issue** — follow
[SECURITY.md](SECURITY.md).

## 7. Licence

Contributions are made under section 4 of [`LICENSE`](LICENSE): you confirm that you wrote your
contribution or have the right to share it, and you grant FreexStudio a perpetual, worldwide,
irrevocable, royalty-free licence to use, modify, publish and distribute it as part of CredMgr,
under any terms FreexStudio chooses. You keep your own copyright. You receive no payment and no
ownership of the software.
