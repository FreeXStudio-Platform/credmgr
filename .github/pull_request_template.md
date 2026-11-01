## What and why

<!-- What does this change, and why does it need to change? Link the issue if there is one. -->

## Which product

- [ ] V2 (Rust — `v2/`)
- [ ] V1 (Node.js — `v1/`, fixes only)
- [ ] Documentation / tooling only

## Checklist

- [ ] Tests for what I changed — `cargo test --workspace` (V2, inside `v2/`) or `npm test` (V1, inside `v1/`) is green
- [ ] V2: `cargo clippy --workspace -- -D warnings`, `cargo fmt --all -- --check` and `cargo deny check` are clean
- [ ] `python3 -m tools.corpus_check` exits 0 (if I touched `v2/docs/`)
- [ ] Secret and personal-data guards are clean — **no credential, no personal path, no project or host name of mine** (see `CONTRIBUTING.md` §1)
- [ ] No secret in a test fixture — generated values only
- [ ] No new dependency (or it is justified above), and nothing that adds a network call to the vault process
- [ ] `CHANGELOG.md` updated under `[Unreleased]`

## What I deliberately did NOT do

<!-- The single most useful line in a PR. It saves the most review time. -->
