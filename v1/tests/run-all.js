'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Ensure age is on PATH
if (!process.env.PATH.includes('/opt/homebrew/bin')) {
  process.env.PATH = '/opt/homebrew/bin:' + process.env.PATH;
}

// ─── Sandbox ─────────────────────────────────────────────────────────────────
// Every test run gets a throwaway CREDMGR_HOME so tests NEVER touch the real
// vault — no _TEST_ residue in the live index, no deletedRefs growth, and a
// failing test can't corrupt real data. Set CREDMGR_TEST_HOME to override.

const ROOT = path.resolve(__dirname, '..');
const sandbox = process.env.CREDMGR_TEST_HOME ||
  fs.mkdtempSync(path.join(os.tmpdir(), 'credmgr-testhome-'));
const childEnv = { ...process.env, CREDMGR_HOME: sandbox };

function seed() {
  const bin = path.join(ROOT, 'bin', 'credmgr');
  execFileSync(process.execPath, [bin, 'init'], { env: childEnv, stdio: 'pipe' });
  // Seed a couple of credentials so list/export/search tests have data.
  execFileSync(process.execPath, [bin, 'set', 'SEED_GLOBAL_KEY', 'seed-value-1', '--project=global'], { env: childEnv, stdio: 'pipe' });
  execFileSync(process.execPath, [bin, 'set', 'SEED_API_TOKEN', 'seed-value-2', '--project=global', '--category=api-key'], { env: childEnv, stdio: 'pipe' });
}

const testFiles = [
  'guard.test.js',
  'paths.test.js',
  'classify.test.js',
  'crypto.test.js',
  'machine-lock.test.js',
  'store.test.js',
  'library.test.js',
  'changelog.test.js',
  'lock.test.js',
  'integrations.test.js',
  'mcp-gate.test.js',
  'mcp-tools.test.js',
  'server.test.js',
  'token-cli.test.js',
  'stress.test.js',
];

let totalPassed = 0;
let totalFailed = 0;

function recordCounts(output) {
  const match = output.match(/(\d+) passed, (\d+) failed/);
  if (!match) return null;
  totalPassed += Number(match[1]);
  totalFailed += Number(match[2]);
  return Number(match[2]);
}

console.log('credmgr test suite  (sandbox: ' + sandbox + ')\n' + '═'.repeat(40));

try {
  seed();

  for (const file of testFiles) {
    const filePath = path.join(__dirname, file);
    try {
      const output = execFileSync(process.execPath, [filePath], {
        encoding: 'utf8',
        cwd: ROOT,
        env: childEnv,
      });
      process.stdout.write(output);

      // Parse results from last line
      if (recordCounts(output) === null) totalFailed++;
    } catch (err) {
      const failures = recordCounts(err.stdout || '');
      if (failures === null || failures === 0) totalFailed++;
      console.error('\nFATAL: ' + file + ' crashed');
      if (err.stdout) process.stdout.write(err.stdout);
      if (err.stderr) process.stderr.write(err.stderr);
    }
  }
} finally {
  // Remove the sandbox unless the caller pinned one for debugging.
  if (!process.env.CREDMGR_TEST_HOME) {
    try { fs.rmSync(sandbox, { recursive: true, force: true }); } catch (_) {}
  }
}

console.log('\n' + '═'.repeat(40));
console.log('Total: ' + totalPassed + ' passed, ' + totalFailed + ' failed');

if (totalFailed > 0) {
  process.exit(1);
}
