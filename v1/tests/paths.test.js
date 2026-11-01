'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');
const paths = require('../lib/paths');
let passed = 0;
let failed = 0;
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'credmgr-paths-'));
const repo = path.join(scratch, 'repo');
fs.mkdirSync(path.join(repo, 'nested'), { recursive: true });
execFileSync('git', ['init', '--quiet', repo]);
const link = path.join(scratch, 'outside-link');
fs.symlinkSync(path.join(repo, 'nested'), link, 'dir');

function test(name, fn) {
  try { fn(); passed++; }
  catch (err) { failed++; console.error('FAIL: ' + name + '\n  ' + err.message); }
}

try {
  test('vault location resolves a symlink into a Git subdirectory', () => {
    assert.throws(() => paths.assertVaultNotInRepo(link), { code: 'VAULT_IN_REPO' });
  });
  test('new vault beneath a symlink into Git is refused before creation', () => {
    assert.throws(() => paths.assertVaultNotInRepo(path.join(link, 'new/vault')), { code: 'VAULT_IN_REPO' });
    assert.ok(!fs.existsSync(path.join(repo, 'nested/new')), 'location check must not create directories');
  });
  test('private temporary directory outside Git remains usable', () => {
    assert.deepStrictEqual(paths.assertVaultNotInRepo(path.join(scratch, 'new/vault')), { ok: true });
  });
} finally { fs.rmSync(scratch, { recursive: true, force: true }); }

console.log('paths.test.js: ' + passed + ' passed, ' + failed + ' failed');
if (failed) process.exit(1);
