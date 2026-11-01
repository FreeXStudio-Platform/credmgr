'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
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
    console.error('  ' + err.message);
  }
}

// ─── randomId ──────────────────────────────────────────────────────────────

test('randomId: default length', () => {
  const id = cryptoLib.randomId();
  assert.strictEqual(id.length, 16); // 8 bytes = 16 hex chars
  assert.ok(/^[a-f0-9]+$/.test(id));
});

test('randomId: custom length', () => {
  const id = cryptoLib.randomId(4);
  assert.strictEqual(id.length, 8);
});

test('randomId: unique', () => {
  const a = cryptoLib.randomId();
  const b = cryptoLib.randomId();
  assert.notStrictEqual(a, b);
});

// ─── encrypt/decrypt round-trip ────────────────────────────────────────────

test('encrypt/decrypt round-trip', () => {
  const plain = 'test-secret-' + Date.now();
  const encrypted = cryptoLib.encrypt(plain);
  const decrypted = cryptoLib.decrypt(encrypted);
  assert.strictEqual(decrypted.trim(), plain);
});

test('encrypt/decrypt multi-line', () => {
  const plain = 'line1\nline2\nline3';
  const encrypted = cryptoLib.encrypt(plain);
  const decrypted = cryptoLib.decrypt(encrypted);
  assert.strictEqual(decrypted.trim(), plain);
});

// ─── encryptToFile/decryptFile ─────────────────────────────────────────────

test('encryptToFile/decryptFile round-trip', () => {
  const plain = 'file-secret-' + Date.now();
  const tmpFile = path.join(os.tmpdir(), 'credmgr-test-' + Date.now() + '.age');

  try {
    cryptoLib.encryptToFile(plain, tmpFile);
    assert.ok(fs.existsSync(tmpFile));
    const decrypted = cryptoLib.decryptFile(tmpFile);
    assert.strictEqual(decrypted.trim(), plain);
  } finally {
    if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
  }
});

// ─── binary-safe round-trip (backup tar path) ──────────────────────────────

test('decryptToBuffer: binary payload survives byte-for-byte', () => {
  // Random bytes deliberately include values ≥ 0x80 — a string round-trip
  // would corrupt these; the Buffer path must not.
  const payload = require('crypto').randomBytes(4096);
  const encrypted = cryptoLib.encrypt(payload);
  const decrypted = cryptoLib.decryptToBuffer(encrypted);
  assert.ok(Buffer.isBuffer(decrypted));
  assert.ok(payload.equals(decrypted), 'binary payload corrupted in round-trip');
});

test('encryptToFile/decryptFileToBuffer: binary file round-trip', () => {
  const payload = require('crypto').randomBytes(2048);
  const tmpFile = path.join(os.tmpdir(), 'credmgr-test-bin-' + Date.now() + '.age');
  try {
    cryptoLib.encryptToFile(payload, tmpFile);
    const decrypted = cryptoLib.decryptFileToBuffer(tmpFile);
    assert.ok(payload.equals(decrypted));
  } finally {
    if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
  }
});

// ─── Machine-lock integration (real `age` binary, not just wrap/unwrap) ────
// lib/machine-lock.js has its own exhaustive unit tests (tests/machine-lock.
// test.js); these two confirm the actual INTEGRATION point — that crypto.js's
// decrypt() really does call through machine-lock and that age itself still
// works end-to-end, not just the isolated wrap/unwrap math. Always disables
// again in `finally` so later tests in this file (and this sandbox run) see
// a normal plaintext identity.

test('machine-lock: real encrypt/decrypt round-trip still works once enabled (same machine)', () => {
  const machineLock = require('../lib/machine-lock');
  const identityPath = cryptoLib.getIdentityPath();
  const opts = { fingerprintOverride: 'crypto-test-machine-same' };
  machineLock.enable(identityPath, opts);
  try {
    assert.strictEqual(machineLock.isEnabled(opts), true);
    const plain = 'machine-locked-secret-' + Date.now();
    const encrypted = cryptoLib.encrypt(plain, opts);
    const decrypted = cryptoLib.decrypt(encrypted, opts);
    assert.strictEqual(decrypted.trim(), plain);
  } finally {
    machineLock.disable(identityPath, opts);
  }
});

test('machine-lock: decrypt() fails with a clear error on a different machine fingerprint', () => {
  const machineLock = require('../lib/machine-lock');
  const identityPath = cryptoLib.getIdentityPath();
  const opts = { fingerprintOverride: 'crypto-test-machine-original' };
  machineLock.enable(identityPath, opts);
  try {
    const encrypted = cryptoLib.encrypt('should-not-decrypt-elsewhere', opts);
    const elsewhere = { fingerprintOverride: 'a-totally-different-machine' };
    assert.throws(() => cryptoLib.decrypt(encrypted, elsewhere), /machine-locked and will not decrypt here/);
    // The correct machine can still read it — the lock isn't just broken outright.
    assert.strictEqual(cryptoLib.decrypt(encrypted, opts).trim(), 'should-not-decrypt-elsewhere');
  } finally {
    machineLock.disable(identityPath, opts);
  }
});

test('machine-lock: no temp identity file survives after decrypt (locked or not)', () => {
  const machineLock = require('../lib/machine-lock');
  const identityPath = cryptoLib.getIdentityPath();
  const opts = { fingerprintOverride: 'crypto-test-machine-cleanup' };
  machineLock.enable(identityPath, opts);
  try {
    const before = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('credmgr-lock-'));
    cryptoLib.decrypt(cryptoLib.encrypt('cleanup-check', opts), opts);
    const after = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('credmgr-lock-'));
    assert.strictEqual(after.length, before.length, 'decrypt must not leave temp identity directories behind');
  } finally {
    machineLock.disable(identityPath, opts);
  }
});

// ─── secureTempFile ────────────────────────────────────────────────────────

test('secureTempFile: unpredictable dir, 0600 file, cleanup works', () => {
  const tmp = cryptoLib.secureTempFile('k', 'v');
  try {
    assert.ok(fs.existsSync(tmp.file));
    const mode = fs.statSync(tmp.file).mode & 0o777;
    assert.strictEqual(mode, 0o600);
    const dirMode = fs.statSync(tmp.dir).mode & 0o777;
    assert.strictEqual(dirMode, 0o700);
  } finally {
    cryptoLib.cleanupTemp(tmp.dir);
  }
  assert.ok(!fs.existsSync(tmp.dir), 'cleanupTemp should remove the dir');
});

test('sha256: stable known digest', () => {
  assert.strictEqual(
    cryptoLib.sha256('abc'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );
});

// ─── verify ────────────────────────────────────────────────────────────────

test('verify: passes with valid setup', () => {
  const result = cryptoLib.verify();
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.errors.length, 0);
});

// ─── getPublicKey ──────────────────────────────────────────────────────────

test('getPublicKey: returns age1... format', () => {
  const pubKey = cryptoLib.getPublicKey();
  assert.ok(pubKey.startsWith('age1'), 'Public key should start with age1');
});

// ─── Summary ───────────────────────────────────────────────────────────────

console.log('\ncrypto.test.js: ' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exit(1);
