# Homebrew formula (prepared, not published)

`credmgr.rb` is a **template** for a formula in a Homebrew tap. It installs the prebuilt, **unsigned**
tarball that `scripts/release.sh` produces and a maintainer attaches to a GitHub Release (`credmgr` and
`credmgrd`, the SBOMs, the docs). It builds nothing, and nothing here creates a repository, a tag or a
release: the tap does not exist yet.

## Status

| Check | Result |
|---|---|
| `brew style packaging/homebrew/credmgr.rb` (the template as written) | no offenses |
| `brew audit --formula --strict` on the template filled from a real `SHA256SUMS`, in a throwaway local tap | passes |
| the same with `--online` | fails on exactly two things, both "not published yet": the repository homepage and the release asset answer 404 |
| `brew install` / `brew test` | **not run.** Installing links a V2 `credmgr` into the Homebrew prefix, where it can shadow another `credmgr` on `PATH`; the `test do` commands (`--version`, `help`) are the same ones `scripts/fresh-install-check.sh` runs against the tarball |
| the `service` block rendered to a launchd plist | **not checked.** Homebrew refuses to load a formula from an unregistered tap, and trusting one is a persistent Homebrew security setting that was left alone |

Only an **Apple Silicon** tarball is built (`aarch64-apple-darwin`), so the formula says
`depends_on arch: :arm64`. An Intel line needs an Intel build and a second URL and hash first.

## Publishing it (operator action)

1. Cut the release: `scripts/release.sh`, then `scripts/fresh-install-check.sh`, then attach the tarball, the SBOMs
   and `SHA256SUMS` to a GitHub Release `v<version>`. (Nothing in this repository does that for you.)
2. Fill the formula from the **published** `SHA256SUMS` - the hash must be that of the uploaded file:

   ```bash
   packaging/homebrew/fill-formula.sh --sums /path/to/published/SHA256SUMS --out /path/to/homebrew-credmgr/Formula/credmgr.rb
   ```

   It reads the `credmgr-<version>-aarch64-apple-darwin.tar.gz` line, writes a **new** file (the template is
   never edited), and refuses a missing, duplicated or all-zero hash, a leftover placeholder, or Ruby that does
   not parse. `--repo OWNER/REPO` points the URLs at another repository.
3. In the tap repository (named `homebrew-credmgr`), check and commit it:

   ```bash
   brew audit --formula --strict --online <owner>/credmgr/credmgr
   brew install <owner>/credmgr/credmgr && brew test credmgr
   ```

Use `brew services start credmgr` **or** the `com.credmgr.brokerd.plist` that ships in the tarball, never both:
a second `credmgrd` refuses a live socket and launchd would keep restarting it.
