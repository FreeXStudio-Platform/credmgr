'use strict';

/**
 * Vault location resolution — cross-platform, and deliberately OUTSIDE the repo.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHY THIS FILE EXISTS
 *
 * Earlier builds resolved the vault home to `path.resolve(__dirname, '..')` —
 * the checkout itself. A fresh `git clone` followed by `credmgr init` therefore
 * wrote `.credmgr/master.key` and `store/vault.age` **inside the working tree**,
 * one `git add -A` away from being published. A `.gitignore` is a promise; a
 * path outside the repository is a guarantee.
 *
 * The vault now lives in the platform's user-data directory. There is no
 * supported configuration in which a new vault is created inside the source
 * tree, and `assertVaultNotInRepo()` refuses to initialise one if you try.
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Resolution order:
 *   1. $CREDMGR_HOME                          — explicit override (tests, portable installs)
 *   2. <repo>/.credmgr/master.key exists      — a pre-existing in-repo install keeps working
 *   3. platform user-data directory           — the default for every new install
 *
 *      macOS    ~/Library/Application Support/credmgr
 *      Windows  %APPDATA%\credmgr
 *      Linux    $XDG_DATA_HOME/credmgr  (default ~/.local/share/credmgr)
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..');

function platformDataDir() {
  const home = os.homedir();
  switch (process.platform) {
    case 'darwin':
      return path.join(home, 'Library', 'Application Support', 'credmgr');
    case 'win32':
      return path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'credmgr');
    default:
      return path.join(process.env.XDG_DATA_HOME || path.join(home, '.local', 'share'), 'credmgr');
  }
}

/** True when this install predates the move and still keeps its vault in-repo. */
function hasLegacyInRepoVault() {
  try {
    return fs.existsSync(path.join(REPO_ROOT, '.credmgr', 'master.key'));
  } catch (_) { return false; }
}

function vaultHome() {
  if (process.env.CREDMGR_HOME) return path.resolve(process.env.CREDMGR_HOME);
  if (hasLegacyInRepoVault()) return REPO_ROOT;
  return platformDataDir();
}

/** Resolve existing ancestors first, then walk upward for a .git marker. */
function findGitRoot(startDir) {
  let dir = path.resolve(startDir);
  const missing = [];
  for (;;) {
    try {
      dir = path.resolve(fs.realpathSync(dir), ...missing.reverse());
      break;
    } catch (err) {
      if (err.code !== 'ENOENT') throw new Error('Cannot resolve vault location safely');
      const parent = path.dirname(dir);
      if (parent === dir) throw new Error('Cannot resolve vault location safely');
      missing.push(path.basename(dir));
      dir = parent;
    }
  }
  for (;;) {
    if (fs.existsSync(path.join(dir, '.git'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/**
 * Refuse to create a NEW vault inside a git repository.
 *
 * Called by `credmgr init`. Existing legacy installs are grandfathered (they
 * return a warning rather than throwing) because breaking someone's working
 * vault is worse than the risk they already live with — but every command
 * prints the warning until they move it.
 */
function assertVaultNotInRepo(home, opts) {
  const dir = home || vaultHome();
  const gitRoot = findGitRoot(dir);
  if (!gitRoot) return { ok: true };

  const legacy = hasLegacyInRepoVault() && path.resolve(dir) === REPO_ROOT;
  const message =
    'Vault location is inside a git repository:\n' +
    '  vault : ' + dir + '\n' +
    '  repo  : ' + gitRoot + '\n' +
    'A credential vault must never live inside a repository — one `git add -A`\n' +
    'publishes it. Move it, or set CREDMGR_HOME to a directory outside the repo:\n' +
    '  export CREDMGR_HOME="' + platformDataDir() + '"';

  if (legacy && !(opts && opts.strict)) return { ok: false, legacy: true, warning: message };
  const err = new Error(message);
  err.code = 'VAULT_IN_REPO';
  throw err;
}

/** Everything a caller might need, resolved once. */
function paths() {
  const home = vaultHome();
  return {
    home,
    credmgrDir: path.join(home, '.credmgr'),
    storeDir: path.join(home, 'store'),
    backupsDir: path.join(home, 'backups'),
    isLegacyInRepo: hasLegacyInRepoVault() && home === REPO_ROOT,
    isExplicit: !!process.env.CREDMGR_HOME,
    platformDefault: platformDataDir(),
    repoRoot: REPO_ROOT,
  };
}

module.exports = {
  vaultHome,
  platformDataDir,
  hasLegacyInRepoVault,
  assertVaultNotInRepo,
  findGitRoot,
  paths,
  REPO_ROOT,
};
