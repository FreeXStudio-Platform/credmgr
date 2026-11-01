# frozen_string_literal: true

# --- template note (fill-formula.sh replaces this block) ---
# Homebrew formula for the CredMgr V2 command-line client and broker (credmgr, credmgrd).
#
# TEMPLATE. Prepared, not published: no tap repository exists yet. The version in the url line (written
# as a double-brace placeholder) and the all-zero sha256 are placeholders, filled from a release's SHA256SUMS by
# packaging/homebrew/fill-formula.sh, which writes a NEW file and never edits this one. An all-zero hash
# is well-formed (so `brew style` can check this file) but can never match a download, so installing the
# unfilled template fails closed with a checksum mismatch.
#
# It installs the PREBUILT, UNSIGNED tarball that scripts/release.sh produces and the maintainer attaches
# to a GitHub Release - it builds nothing. Only an Apple Silicon tarball is built today, so the formula
# says so; an Intel line needs an Intel build first (see README.md here).
# --- end template note ---
class Credmgr < Formula
  desc "Local, offline credential vault: command-line client and broker"
  homepage "https://github.com/FreeXStudio-Platform/credmgr"
  url "https://github.com/FreeXStudio-Platform/credmgr/releases/download/v{{VERSION}}/credmgr-{{VERSION}}-aarch64-apple-darwin.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license :cannot_represent

  depends_on arch: :arm64
  depends_on :macos

  def install
    bin.install "bin/credmgr", "bin/credmgrd"
    doc.install "RELEASE.md", "CHANGELOG.md", "SECURITY.md"
    pkgshare.install "sbom"
  end

  # `brew services start credmgr` runs the broker under launchd. The tarball also ships
  # packaging/com.credmgr.brokerd.plist for people who do not use Homebrew - use one or the other,
  # never both: a second credmgrd refuses a live socket and launchd would restart it forever.
  service do
    run opt_bin/"credmgrd"
    keep_alive true
    process_type :interactive
    log_path var/"log/credmgrd.log"
    error_log_path var/"log/credmgrd.log"
  end

  def caveats
    <<~EOS
      CredMgr is a pre-release. These binaries are UNSIGNED and your vault key is protected by your
      passphrase alone (no Secure Enclave) - read the known limitations before trusting it with anything
      that matters:
        #{doc}/RELEASE.md

      Start the broker, then create a vault (it prints a recovery code ONCE - write it down):
        brew services start credmgr
        credmgr init

      The broker locks the vault whenever it restarts. The desktop app is a separate preview download and
      needs this broker running; it is not part of this formula.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/credmgr --version")
    assert_match version.to_s, shell_output("#{bin}/credmgrd --version")
    assert_match "credmgr init", shell_output("#{bin}/credmgr help")
  end
end
