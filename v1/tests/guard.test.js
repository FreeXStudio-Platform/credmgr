'use strict';

// These are real Git-index/hook checks. Every credential-shaped value is
// generated synthetic data in a throwaway repository, never a live credential.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const source = path.resolve(__dirname, '../scripts/guard-no-secrets.mjs');
const secret = 'ghp_' + 'A'.repeat(36);
let passed = 0;
let failed = 0;

function git(repo, args) {
  return execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function fixture(nested = true) {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'credmgr-guard-'));
  git(repo, ['init', '--quiet']);
  git(repo, ['config', 'user.name', 'Guard Test']);
  git(repo, ['config', 'user.email', 'guard-test@example.invalid']);
  const pkg = nested ? path.join(repo, 'v1') : repo;
  fs.mkdirSync(path.join(pkg, 'scripts'), { recursive: true });
  const script = path.join(pkg, 'scripts/guard-no-secrets.mjs');
  fs.copyFileSync(source, script);
  const write = (name, text) => {
    const file = path.join(pkg, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text);
    return file;
  };
  const stage = (name) => git(repo, ['add', '--', path.relative(repo, path.join(pkg, name))]);
  const run = (args = [], cwd = pkg) => spawnSync(process.execPath, [script, ...args], {
    cwd, encoding: 'utf8', timeout: 15000,
  });
  return { repo, pkg, script, write, stage, run };
}

function test(name, fn, nested = true) {
  const f = fixture(nested);
  try { fn(f); passed++; }
  catch (err) { failed++; console.error('FAIL: ' + name + '\n  ' + err.message); }
  finally { fs.rmSync(f.repo, { recursive: true, force: true }); }
}

function blocked(result, code = 1) {
  assert.strictEqual(result.status, code, 'expected guard to block; exit=' + result.status);
  assert.ok(!(result.stdout + result.stderr).includes(secret), 'must not print matched credential');
}

test('nested staged file is scanned when invoked from repository root', f => {
  f.write('notes.txt', secret); f.stage('notes.txt');
  blocked(f.run([], f.repo));
});
test('staged blob remains blocked after working file is sanitized', f => {
  f.write('notes.txt', secret); f.stage('notes.txt'); f.write('notes.txt', 'clean');
  blocked(f.run());
});
test('staged blob remains blocked after working file is removed', f => {
  const file = f.write('notes.txt', secret); f.stage('notes.txt'); fs.unlinkSync(file);
  blocked(f.run());
});
test('unstaged credential cannot change a clean staged blob', f => {
  f.write('notes.txt', 'clean'); f.stage('notes.txt'); f.write('notes.txt', secret);
  assert.strictEqual(f.run().status, 0);
});
test('NUL-delimited Git paths preserve newline and unicode names', f => {
  const name = 'odd\n雪 name.txt'; f.write(name, secret); f.stage(name);
  blocked(f.run());
});
test('quoted forbidden staged pathname remains blocked', f => {
  const name = 'odd\nname/.env'; f.write(name, 'clean'); f.stage(name);
  blocked(f.run());
});
test('large staged blob fails closed rather than being skipped', f => {
  f.write('large.txt', 'x'.repeat(2 * 1024 * 1024 + 1)); f.stage('large.txt');
  blocked(f.run(), 2);
});
test('credential-shaped bytes in binary files are scanned', f => {
  f.write('binary.bin', Buffer.from('\0' + secret)); f.stage('binary.bin');
  blocked(f.run());
});
test('source and documentation filenames are not blanket exemptions', f => {
  f.write('lib/classify.js', secret); f.stage('lib/classify.js');
  blocked(f.run());
});
test('renamed age identities are detected by content', f => {
  const identity = 'AGE-SECRET-' + 'KEY-1' + 'A'.repeat(58);
  f.write('notes.txt', identity); f.stage('notes.txt');
  const result = f.run(); blocked(result);
  assert.ok(!(result.stdout + result.stderr).includes(identity));
});
test('--all refuses parent symlinks that escape package scope', f => {
  f.write('notes/entry.txt', 'clean'); f.stage('notes/entry.txt');
  fs.mkdirSync(path.join(f.repo, 'excluded'));
  fs.writeFileSync(path.join(f.repo, 'excluded/entry.txt'), secret);
  fs.rmSync(path.join(f.pkg, 'notes'), { recursive: true });
  fs.symlinkSync(path.join(f.repo, 'excluded'), path.join(f.pkg, 'notes'));
  blocked(f.run(['--all']), 2);
});
test('--all scans only the package regardless of invocation directory', f => {
  fs.mkdirSync(path.join(f.repo, 'excluded'));
  fs.writeFileSync(path.join(f.repo, 'excluded/secret.txt'), secret);
  git(f.repo, ['add', '--', 'excluded/secret.txt']);
  f.write('notes.txt', 'clean'); f.stage('notes.txt');
  const result = f.run(['--all'], f.repo);
  assert.strictEqual(result.status, 0, 'excluded sibling must not be scanned');
  assert.ok(!result.stderr.includes('excluded'));
});
test('--all scans untracked files in a fresh package', f => {
  f.write('notes.txt', secret); blocked(f.run(['--all']));
});
test('package at Git root scans staged blobs too', f => {
  f.write('notes.txt', secret); f.stage('notes.txt'); f.write('notes.txt', 'clean');
  blocked(f.run());
}, false);
test('installed nested hook runs during a real commit', f => {
  assert.strictEqual(f.run(['--install']).status, 0);
  f.write('notes.txt', 'clean'); f.stage('notes.txt');
  const clean = spawnSync('git', ['commit', '--quiet', '-m', 'clean'], { cwd: f.repo, encoding: 'utf8' });
  assert.strictEqual(clean.status, 0, 'nested hook must permit clean commit: ' + clean.stderr);
  f.write('notes.txt', secret); f.stage('notes.txt'); f.write('notes.txt', 'clean');
  const bad = spawnSync('git', ['commit', '--quiet', '-m', 'blocked'], { cwd: f.repo, encoding: 'utf8' });
  blocked(bad);
});
test('installer respects repository core.hooksPath', f => {
  git(f.repo, ['config', 'core.hooksPath', '.custom-hooks']);
  assert.strictEqual(f.run(['--install']).status, 0);
  assert.ok(fs.existsSync(path.join(f.repo, '.custom-hooks/pre-commit')));
});
test('bounded 256-file staged scan finds the final staged-only credential', f => {
  for (let i = 0; i < 256; i++) f.write('batch/file-' + i + '.txt', i === 255 ? secret : 'clean');
  git(f.repo, ['add', '--', 'v1/batch']);
  f.write('batch/file-255.txt', 'clean');
  blocked(f.run());
  assert.strictEqual(f.run(['--all']).status, 0, 'working tree and index scans have distinct inputs');
});

console.log('guard.test.js: ' + passed + ' passed, ' + failed + ' failed');
if (failed) process.exit(1);
