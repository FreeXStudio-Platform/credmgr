#!/usr/bin/env node
/**
 * guard-no-secrets — the third line of defence against publishing a credential.
 *
 *   1st  the vault lives outside the repository        (lib/paths.js)
 *   2nd  .gitignore denies every secret shape by default
 *   3rd  THIS — blocks the commit, and fails CI
 *
 * Usage:
 *   node scripts/guard-no-secrets.mjs            # scan staged changes (pre-commit)
 *   node scripts/guard-no-secrets.mjs --all      # scan the whole working tree (CI)
 *   node scripts/guard-no-secrets.mjs --install  # install the git pre-commit hook
 *
 * Exit codes: 0 clean · 1 findings · 2 usage/environment error.
 *
 * DESIGN NOTES
 * - Fails CLOSED. If it cannot determine what is being committed, it blocks.
 * - Reports the file and line but NEVER prints the matched secret.
 * - Allowlist is narrow and explicit; there is no `--force`. If you genuinely
 *   need to commit something that trips a rule, add a precise `credmgr-allow`
 *   comment on the line and explain why in the commit message.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, readlinkSync, realpathSync, lstatSync, writeFileSync, chmodSync, mkdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MAX_BYTES = 2 * 1024 * 1024;      // larger files require review, never silently skip
const ALLOW_MARK = 'credmgr-allow';      // escape hatch — must carry a written justification
const ALLOW_WINDOW = 5;                  // lines above a match the marker may appear in

// ── Path rules: these must never be committed, whatever they contain ────────
const FORBIDDEN_PATHS = [
  { re: /(^|\/)\.credmgr(\/|$)/,            why: 'vault key directory' },
  { re: /(^|\/)store\/(index\.json|vault)/, why: 'vault store' },
  { re: /(^|\/)backups?(\/|$)/,             why: 'vault backups' },
  { re: /\.age$/,                           why: 'age-encrypted blob' },
  { re: /\.(pem|p12|pfx|keystore|jks|kubeconfig)$/, why: 'key material' },
  { re: /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/, why: 'private SSH key' },
  { re: /(^|\/)\.env($|\.(?!example$|sample$|template$))/, why: 'environment file' },
  { re: /(^|\/)(credentials|service-account.*|gcp-key.*|firebase-adminsdk-.*)\.json$/, why: 'cloud credential file' },
  { re: /(^|\/)\.(npmrc|netrc)$/,           why: 'may contain auth tokens' },
];

// ── Content rules: high-confidence secret shapes ────────────────────────────
const CONTENT_RULES = [
  { id: 'private-key',   re: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/ },
  { id: 'age-identity',  re: /\bAGE-SECRET-KEY-1[0-9A-Z]{20,}\b/ },
  { id: 'aws-akid',      re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'aws-secret',    re: /aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}/i },
  { id: 'anthropic',     re: /\bsk-ant-[A-Za-z0-9_-]{20,}/ },
  { id: 'openai',        re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/ },
  { id: 'github-token',  re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{50,}/ },
  { id: 'slack',         re: /\bxox[abprs]-[0-9A-Za-z-]{10,}/ },
  { id: 'google-api',    re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: 'stripe',        re: /\b(?:sk|rk)_live_[0-9A-Za-z]{24,}/ },
  { id: 'jwt',           re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { id: 'evm-privkey',   re: /\b(?:0x)?[a-fA-F0-9]{64}\b(?=.*(?:priv|secret|key|wallet|mnemonic))/i },
  { id: 'bip39-seed',    re: /\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b(?=.*(?:mnemonic|seed|recovery))/i },
  { id: 'pg-url',        re: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s@/]+@/ },
];

// Anchor scope to this package, not the hook's working directory. A nested
// installation must never enumerate sibling packages or follow their symlinks.
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let repoRoot;
let scope;

function git(args) {
  return execFileSync('git', args, {
    cwd: repoRoot || PACKAGE_ROOT, encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function initializeRepo() {
  try {
    repoRoot = git(['rev-parse', '--show-toplevel']).trim();
    const relative = path.relative(repoRoot, PACKAGE_ROOT).split(path.sep).join('/');
    if (relative.startsWith('../') || path.isAbsolute(relative)) throw new Error('outside repository');
    scope = relative ? ':(top,literal)' + relative + '/' : '.';
  } catch {
    console.error('guard-no-secrets: not a git repository, or git is unavailable.');
    process.exit(2);
  }
}

function splitPaths(output) { return output.split('\0').filter(Boolean); }

function stagedFiles() {
  const changed = splitPaths(git(['diff', '--cached', '--name-only', '-z', '--diff-filter=ACMRTUXB', '--', scope]));
  const entries = new Map();
  for (const record of splitPaths(git(['ls-files', '--stage', '-z', '--', scope]))) {
    const tab = record.indexOf('\t');
    const [mode, oid, stage] = record.slice(0, tab).split(' ');
    const file = record.slice(tab + 1);
    if (stage !== '0') throw new Error('Unresolved index entry: ' + JSON.stringify(file));
    entries.set(file, { mode, oid });
  }
  return changed.map(file => {
    const entry = entries.get(file);
    if (!entry || !['100644', '100755', '120000'].includes(entry.mode)) {
      throw new Error('Cannot scan index entry: ' + JSON.stringify(file));
    }
    return { file, oid: entry.oid };
  });
}

// Include untracked, non-ignored package files before a first commit too.
function trackedFiles() {
  const tracked = splitPaths(git(['ls-files', '-z', '--', scope]));
  const untracked = splitPaths(git(['ls-files', '-z', '--others', '--exclude-standard', '--', scope]));
  return [...new Set([...tracked, ...untracked])].map(file => ({ file }));
}

function readContent(entry) {
  if (entry.oid) {
    const size = Number(git(['cat-file', '-s', entry.oid]).trim());
    if (!Number.isSafeInteger(size) || size > MAX_BYTES) throw new Error('Staged file exceeds scan limit: ' + JSON.stringify(entry.file));
    return git(['cat-file', 'blob', entry.oid]);
  }
  const absolute = path.join(repoRoot, entry.file);
  let parent;
  try { parent = realpathSync(path.dirname(absolute)); }
  catch (err) {
    if (err.code === 'ENOENT') return null;
    throw new Error('Cannot resolve file directory: ' + JSON.stringify(entry.file));
  }
  const relative = path.relative(PACKAGE_ROOT, parent);
  if (relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) {
    throw new Error('File directory escapes package scope: ' + JSON.stringify(entry.file));
  }
  let st;
  try { st = lstatSync(absolute); }
  catch (err) {
    if (err.code === 'ENOENT') return null; // tracked file deleted in the working tree
    throw new Error('Cannot read file: ' + JSON.stringify(entry.file));
  }
  if (st.size > MAX_BYTES) throw new Error('File exceeds scan limit: ' + JSON.stringify(entry.file));
  // A committed symlink contains its target string, not the target's bytes.
  if (st.isSymbolicLink()) return readlinkSync(absolute);
  if (!st.isFile()) throw new Error('Cannot scan file type: ' + JSON.stringify(entry.file));
  try { return readFileSync(absolute, 'utf8'); }
  catch { throw new Error('Cannot read file: ' + JSON.stringify(entry.file)); }
}

function scan(files) {
  const findings = [];

  for (const entry of files) {
    const { file } = entry;
    for (const rule of FORBIDDEN_PATHS) {
      if (rule.re.test(file)) findings.push({ file, line: 0, rule: 'path', why: rule.why });
    }

    const text = readContent(entry);
    if (text === null) continue;
    const lines = text.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // The allow marker may sit on the matching line, or anywhere in the five
      // lines above it — a real justification needs a few sentences, and forcing
      // it onto the end of the offending line makes people write "ok" instead of
      // a reason. Five lines is enough for a proper comment block and still far
      // too narrow to silently cover an unrelated line further down.
      let allowed = false;
      for (let j = Math.max(0, i - ALLOW_WINDOW); j <= i; j++) {
        if (lines[j].includes(ALLOW_MARK)) { allowed = true; break; }
      }
      if (allowed) continue;
      for (const rule of CONTENT_RULES) {
        if (rule.re.test(line)) {
          findings.push({ file, line: i + 1, rule: rule.id, why: 'looks like a live secret' });
          break;                           // one finding per line is enough
        }
      }
    }
  }
  return findings;
}

function installHook() {
  const hooksDir = path.resolve(repoRoot, git(['rev-parse', '--git-path', 'hooks']).trim());
  mkdirSync(hooksDir, { recursive: true });
  const hookPath = path.join(hooksDir, 'pre-commit');
  const relative = path.relative(repoRoot, fileURLToPath(import.meta.url)).split(path.sep).join('/');
  const quoted = "'" + relative.replace(/'/g, "'\\''") + "'";
  const hook = '#!/bin/sh\n' +
    '# installed by credmgr — blocks commits containing credentials\n' +
    'repo_root=$(git rev-parse --show-toplevel) || exit 1\n' +
    'node "$repo_root"/' + quoted + ' || exit 1\n';

  if (existsSync(hookPath)) {
    const existing = readFileSync(hookPath, 'utf8');
    if (existing === hook) {
      console.log('pre-commit hook already installed.');
      return;
    }
    writeFileSync(hookPath + '.credmgr-backup', existing);
    console.log('existing pre-commit hook backed up to pre-commit.credmgr-backup');
  }

  writeFileSync(hookPath, hook);
  chmodSync(hookPath, 0o755);
  console.log('✓ pre-commit hook installed at ' + hookPath);
}

// ── main ───────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
if (argv.length > 1 || (argv.length === 1 && !['--all', '--install'].includes(argv[0]))) {
  console.error('Usage: guard-no-secrets.mjs [--all | --install]');
  process.exit(2);
}
initializeRepo();
try {
  if (argv.includes('--install')) { installHook(); process.exit(0); }

  const all = argv.includes('--all');
  const files = all ? trackedFiles() : stagedFiles();

  if (!all && files.length === 0) process.exit(0);

  const findings = scan(files);

  if (findings.length === 0) {
    console.log(`guard-no-secrets: ✓ clean (${files.length} file${files.length === 1 ? '' : 's'} scanned)`);
    process.exit(0);
  }

  console.error('\n╔══════════════════════════════════════════════════════════════════╗');
  console.error('║  COMMIT BLOCKED — possible credentials detected                  ║');
  console.error('╚══════════════════════════════════════════════════════════════════╝\n');
  for (const f of findings) {
    console.error(`  ${JSON.stringify(f.file)}${f.line ? ':' + f.line : ''}`);
    console.error(`      rule: ${f.rule} — ${f.why}\n`);
  }
  console.error('The matched values are deliberately NOT printed.\n');
  console.error('What to do:');
  console.error('  • A real secret?  Remove it, then put it in the vault:  credmgr set <NAME>');
  console.error('  • Vault file?     It belongs outside the repo — see:    credmgr where');
  console.error('  • False positive? Put a `' + ALLOW_MARK + '` comment on that line, or in a');
  console.error('                    comment within the 5 lines above it, saying WHY it is safe.\n');
  process.exit(1);
} catch (err) {
  // Never echo subprocess output or a buffer that could contain a secret.
  const message = err && !('stdout' in err) && !('stderr' in err) ? err.message : 'Git or file scan failed';
  console.error('guard-no-secrets: cannot complete scan — ' + message);
  process.exit(2);
}
