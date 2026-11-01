# doc-system git hooks

Index-level enforcement for the doc-system classification moat (RULEBOOK L14 / CLASSIFICATION.md).

## `staged_content_scanner.py` — confidential-doc placement guard

Blocks a commit/push when a document whose doc-system header declares
`classification: confidential` or `classification: secret` is **staged outside**
`docs/confidential/`. Non-public docs may only live in the confidential vault; this
hook is the last-line, index-level check that they never leak into a tracked public path.

Key properties:

- **Reads STAGED bytes** (`git show :<path>`), not the working tree — it checks exactly what
  would be committed, so a clean working-tree copy cannot mask a classified staged blob.
- **Header is authority** — classification comes from `classification.parse_header` (the same
  parser the render engine uses), not from the filename. A `public`-named file with a `secret`
  header is still blocked.
- **Fail-closed** — a staged file that git reports but whose blob cannot be read is a blocking
  finding, never silently skipped.
- **Deterministic + read-only** — no writes, no network; findings sorted by path.

Header-less Markdown files (ordinary READMEs) and non-Markdown files are ignored — only a genuine
non-public classification header outside the vault blocks.

### Run manually

```bash
.venv/bin/python -m tools.docgen.hooks.staged_content_scanner
# exit 0 = clean, 1 = blocked (classified doc outside the vault), 2 = usage/IO error (not a git repo)
```

### Install as a hook

```bash
cp tools/docgen/hooks/pre-commit.sample .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
# (also usable as a pre-push hook — copy to .git/hooks/pre-push instead / as well)
```

### Public API (importable, testable)

- `iter_staged_files(repo_root) -> list[str]`
- `read_staged_bytes(repo_root, rel_path) -> bytes | None`
- `is_inside_confidential_dir(rel_path) -> bool`
- `scan_staged(repo_root, *, files=None) -> list[Finding]`
- `main(argv=None) -> int`
