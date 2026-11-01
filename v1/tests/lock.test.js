'use strict';

// Unit tests for lib/lock.js — PIN storage (scrypt), unlock sessions,
// config merge-preservation, and the auth rate limiter.

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const lock = require('../lib/lock');
const cryptoLib = require('../lib/crypto');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
  } catch (err) {
    failed++;
    console.error('FAIL: ' + name);
    console.error('  ' + (err && err.message ? err.message : err));
  }
}

const CONFIG_PATH = path.join(cryptoLib.CREDMGR_DIR, 'config.json');

function cleanupPin() {
  // Remove pin/lockTimeout keys directly (test-only; production goes through removePin)
  if (fs.existsSync(CONFIG_PATH)) {
    const cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    delete cfg.pin;
    delete cfg.lockTimeoutMinutes;
    delete cfg.requirePinForAgents;
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
  }
  lock.revokeAllSessions();
  lock._resetRateLimiter();
}

// ─── PIN lifecycle ───────────────────────────────────────────────────────────

test('no PIN by default', () => {
  cleanupPin();
  assert.strictEqual(lock.hasPin(), false);
  assert.strictEqual(lock.verifyPin('1234'), false);
});

test('setPin → hasPin, verifyPin right/wrong', () => {
  cleanupPin();
  lock.setPin('4321', '', {});
  assert.strictEqual(lock.hasPin(), true);
  assert.strictEqual(lock.verifyPin('4321'), true);
  assert.strictEqual(lock.verifyPin('0000'), false);
  assert.strictEqual(lock.verifyPin(''), false);
});

test('PIN hash at rest is scrypt, never the raw PIN', () => {
  const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
  assert.ok(!raw.includes('4321'), 'raw PIN must not appear in config.json');
  const cfg = JSON.parse(raw);
  assert.strictEqual(cfg.pin.algo, 'scrypt');
  assert.ok(cfg.pin.salt && cfg.pin.hash);
});

test('config.json keeps keyPath/pubKeyPath after PIN write (crypto still works)', () => {
  const cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  assert.ok(cfg.keyPath, 'keyPath must survive the PIN write');
  assert.ok(cfg.pubKeyPath, 'pubKeyPath must survive the PIN write');
  // The real proof: encryption round-trip still functions with the merged config
  const enc = cryptoLib.encrypt('lock-config-roundtrip');
  assert.strictEqual(cryptoLib.decrypt(enc), 'lock-config-roundtrip');
});

test('changing PIN requires the current PIN', () => {
  assert.throws(() => lock.setPin('9999', 'wrong', {}), /incorrect/i);
  lock.setPin('9999', '4321', {});
  assert.strictEqual(lock.verifyPin('9999'), true);
  assert.strictEqual(lock.verifyPin('4321'), false);
});

test('PIN rotation revokes previously issued unlock sessions', () => {
  const sid = lock.createSession();
  assert.strictEqual(lock.validateSession(sid), true);
  lock.setPin('9999', '9999', {});
  assert.strictEqual(lock.validateSession(sid), false, 'PIN rotation must revoke old sessions');
});

test('damaged security config fails closed instead of disabling PIN and export password', () => {
  const original = fs.readFileSync(CONFIG_PATH);
  try {
    fs.writeFileSync(CONFIG_PATH, '{"pin":');
    assert.throws(() => lock.hasPin(), /security configuration/i);
    assert.throws(() => lock.hasExportPassword(), /security configuration/i);
  } finally { fs.writeFileSync(CONFIG_PATH, original); }
});

test('PIN length bounds enforced', () => {
  assert.throws(() => lock.setPin('123', '9999', {}), /4–64/);
  assert.throws(() => lock.setPin('x'.repeat(65), '9999', {}), /4–64/);
});

test('malformed agent PIN policy cannot silently disable the gate', () => {
  const original = fs.readFileSync(CONFIG_PATH);
  try {
    for (const value of ['true', 1, null, [], {}]) {
      const cfg = JSON.parse(original.toString());
      cfg.requirePinForAgents = value;
      fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg));
      assert.throws(() => lock.getSettings(), /security configuration/i);
    }
  } finally { fs.writeFileSync(CONFIG_PATH, original); }
});

test('removePin requires current PIN and clears sessions', () => {
  const sid = lock.createSession();
  assert.strictEqual(lock.validateSession(sid), true);
  assert.throws(() => lock.removePin('wrong', {}), /incorrect/i);
  lock.removePin('9999', {});
  assert.strictEqual(lock.hasPin(), false);
  assert.strictEqual(lock.validateSession(sid), false, 'sessions revoked on PIN removal');
});

// ─── Sessions ────────────────────────────────────────────────────────────────

test('session create/validate/revoke lifecycle', () => {
  cleanupPin();
  const sid = lock.createSession();
  assert.strictEqual(typeof sid, 'string');
  assert.strictEqual(sid.length, 64, '32 random bytes as hex');
  assert.strictEqual(lock.validateSession(sid), true);
  lock.revokeSession(sid);
  assert.strictEqual(lock.validateSession(sid), false);
});

test('unknown/garbage session ids are invalid', () => {
  assert.strictEqual(lock.validateSession('not-a-session'), false);
  assert.strictEqual(lock.validateSession(null), false);
  assert.strictEqual(lock.validateSession(undefined), false);
  assert.strictEqual(lock.validateSession(''), false);
});

test('lockTimeoutMinutes setting round-trips and bounds are enforced', () => {
  lock.setLockTimeout(30, {});
  assert.strictEqual(lock.getSettings().lockTimeoutMinutes, 30);
  assert.throws(() => lock.setLockTimeout(0, {}), /between/);
  assert.throws(() => lock.setLockTimeout(100000, {}), /between/);
  cleanupPin();
  assert.strictEqual(lock.getSettings().lockTimeoutMinutes, lock.DEFAULT_TTL_MINUTES);
});

// ─── Export password ─────────────────────────────────────────────────────────

function cleanupExportPassword() {
  if (fs.existsSync(CONFIG_PATH)) {
    const cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    delete cfg.exportPassword;
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
  }
  lock._resetRateLimiter();
}

test('no export password by default', () => {
  cleanupExportPassword();
  assert.strictEqual(lock.hasExportPassword(), false);
  assert.strictEqual(lock.verifyExportPassword('anything'), false);
});

test('setExportPassword requires 8+ characters', () => {
  cleanupExportPassword();
  assert.throws(() => lock.setExportPassword('short1', '', {}), /8–128/);
});

test('setExportPassword → hasExportPassword, verify right/wrong', () => {
  cleanupExportPassword();
  lock.setExportPassword('correct-horse-battery', '', {});
  assert.strictEqual(lock.hasExportPassword(), true);
  assert.strictEqual(lock.verifyExportPassword('correct-horse-battery'), true);
  assert.strictEqual(lock.verifyExportPassword('wrong-password-entirely'), false);
  assert.strictEqual(lock.verifyExportPassword(''), false);
});

test('export password hash at rest is scrypt, never the raw password', () => {
  const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
  assert.ok(!raw.includes('correct-horse-battery'), 'raw export password must not appear in config.json');
});

test('changing the export password requires the current one', () => {
  assert.throws(() => lock.setExportPassword('brand-new-password-here', 'wrong-current', {}),
    /incorrect/);
  lock.setExportPassword('brand-new-password-here', 'correct-horse-battery', {});
  assert.strictEqual(lock.verifyExportPassword('brand-new-password-here'), true);
  assert.strictEqual(lock.verifyExportPassword('correct-horse-battery'), false, 'old password must stop working');
});

test('export password is independent of the vault PIN', () => {
  cleanupPin();
  lock.setPin('9999', '', {});
  assert.strictEqual(lock.hasExportPassword(), true, 'export password set earlier must be unaffected by PIN changes');
  assert.strictEqual(lock.verifyPin('9999'), true);
  assert.strictEqual(lock.verifyExportPassword('brand-new-password-here'), true);
  cleanupPin();
  cleanupExportPassword();
});

test('removeExportPassword requires the current password', () => {
  cleanupExportPassword();
  lock.setExportPassword('remove-me-password', '', {});
  assert.throws(() => lock.removeExportPassword('wrong', {}), /incorrect/);
  lock.removeExportPassword('remove-me-password', {});
  assert.strictEqual(lock.hasExportPassword(), false);
  cleanupExportPassword();
});

// ─── Rate limiter ────────────────────────────────────────────────────────────

test('rate limiter blocks after 5 failures, resets on success', () => {
  lock._resetRateLimiter();
  const key = 'test:client';
  for (let i = 0; i < 4; i++) lock.recordFailure(key);
  assert.strictEqual(lock.blockedMs(key), 0, 'not blocked below threshold');
  lock.recordFailure(key); // 5th
  const blocked = lock.blockedMs(key);
  assert.ok(blocked > 0 && blocked <= 30 * 1000, '5th failure → ~30s block, got ' + blocked);
  lock.recordSuccess(key);
  assert.strictEqual(lock.blockedMs(key), 0, 'success clears the counter');
});

test('rate limiter delay doubles per failure past the threshold', () => {
  lock._resetRateLimiter();
  const key = 'test:doubling';
  for (let i = 0; i < 6; i++) lock.recordFailure(key); // 6th failure
  const blocked = lock.blockedMs(key);
  assert.ok(blocked > 30 * 1000 && blocked <= 60 * 1000, '6th failure → ~60s block, got ' + blocked);
  lock._resetRateLimiter();
});

console.log('lock.test.js: ' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exit(1);
