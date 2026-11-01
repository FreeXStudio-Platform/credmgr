'use strict';

// Unit tests for lib/machine-lock.js — wrap/unwrap correctness, the
// enable/disable file mutation (atomic + self-verifying), and the actual
// security property: unwrapping with the WRONG fingerprint must fail, not
// silently succeed. Every test uses fingerprintOverride so none of this
// depends on (or touches) the real machine's actual hardware/OS identity,
// and every identity file used is a disposable temp file — never the real
// vault's master.key.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const machineLock = require('../lib/machine-lock');

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

const FAKE_AGE_KEY =
  '# created: 2026-01-01T00:00:00Z\n' +
  '# public key: age1faketestkeyfortestingonlyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n' +
// credmgr-allow: deliberately invalid synthetic age identity for wrap/unwrap tests.
  'AGE-SECRET-KEY-1FAKETESTKEYFORTESTINGONLYXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n';

function tempIdentityFile(contents) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'credmgr-mltest-'));
  const file = path.join(dir, 'master.key');
  fs.writeFileSync(file, contents == null ? FAKE_AGE_KEY : contents, { mode: 0o600 });
  return { dir, file };
}

function tempConfigOpts(dir) {
  return { fingerprintOverride: 'test-machine-A', configPath: path.join(dir, 'config.json') };
}

// ─── wrap / unwrap round trip ───────────────────────────────────────────────

test('wrapIdentity/unwrapIdentity round-trips exact plaintext', () => {
  const wrapped = machineLock.wrapIdentity(FAKE_AGE_KEY, 'test-machine-A');
  assert.strictEqual(wrapped.marker, 'credmgr-machine-locked-v1');
  const back = machineLock.unwrapIdentity(wrapped, 'test-machine-A');
  assert.strictEqual(back, FAKE_AGE_KEY);
});

test('unwrapIdentity with the WRONG fingerprint fails — the actual security property', () => {
  const wrapped = machineLock.wrapIdentity(FAKE_AGE_KEY, 'test-machine-A');
  assert.throws(() => machineLock.unwrapIdentity(wrapped, 'test-machine-B'),
    'wrapping for machine A must not unwrap for machine B');
});

test('a tampered ciphertext fails GCM auth-tag verification (not silently garbage)', () => {
  const wrapped = machineLock.wrapIdentity(FAKE_AGE_KEY, 'test-machine-A');
  const tampered = Object.assign({}, wrapped, {
    ciphertext: wrapped.ciphertext.slice(0, -2) + (wrapped.ciphertext.slice(-2) === '00' ? '01' : '00'),
  });
  assert.throws(() => machineLock.unwrapIdentity(tampered, 'test-machine-A'),
    'a flipped ciphertext byte must fail authenticated decryption, not decrypt to garbage');
});

test('unwrapIdentity rejects a non-wrapped/garbage object', () => {
  assert.throws(() => machineLock.unwrapIdentity({ not: 'wrapped' }, 'test-machine-A'), /marker/);
  assert.throws(() => machineLock.unwrapIdentity(null, 'test-machine-A'), /marker/);
});

// ─── enable / disable (real file mutation) ─────────────────────────────────

test('enable() wraps the identity file; disable() restores exact original bytes', () => {
  const { dir, file } = tempIdentityFile();
  const opts = tempConfigOpts(dir);
  try {
    assert.strictEqual(machineLock.isEnabled(opts), false);
    machineLock.enable(file, opts);
    assert.strictEqual(machineLock.isEnabled(opts), true);

    const onDisk = fs.readFileSync(file, 'utf8');
    assert.ok(!onDisk.includes('AGE-SECRET-KEY-'), 'the raw key must not appear in the wrapped file');
    const parsed = JSON.parse(onDisk);
    assert.strictEqual(parsed.marker, 'credmgr-machine-locked-v1');

    machineLock.disable(file, opts);
    assert.strictEqual(machineLock.isEnabled(opts), false);
    assert.strictEqual(fs.readFileSync(file, 'utf8'), FAKE_AGE_KEY, 'disable must restore byte-identical plaintext');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('enable() refuses to run twice', () => {
  const { dir, file } = tempIdentityFile();
  const opts = tempConfigOpts(dir);
  try {
    machineLock.enable(file, opts);
    assert.throws(() => machineLock.enable(file, opts), /already enabled/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('enable() refuses a file that does not look like a plaintext age key', () => {
  const { dir, file } = tempIdentityFile('not an age key at all');
  const opts = tempConfigOpts(dir);
  try {
    assert.throws(() => machineLock.enable(file, opts), /does not look like/);
    assert.strictEqual(fs.readFileSync(file, 'utf8'), 'not an age key at all', 'file must be untouched on refusal');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('disable() refuses when not enabled', () => {
  const { dir, file } = tempIdentityFile();
  const opts = tempConfigOpts(dir);
  try {
    assert.throws(() => machineLock.disable(file, opts), /not enabled/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('disable() with the WRONG fingerprint fails and leaves the file wrapped (recoverable)', () => {
  const { dir, file } = tempIdentityFile();
  const opts = tempConfigOpts(dir);
  try {
    machineLock.enable(file, opts);
    const wrongOpts = Object.assign({}, opts, { fingerprintOverride: 'test-machine-WRONG' });
    assert.throws(() => machineLock.disable(file, wrongOpts));
    // Critically: the file must still be the valid wrapped form, not corrupted —
    // disable() must fail BEFORE touching the on-disk file.
    const stillWrapped = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.strictEqual(stillWrapped.marker, 'credmgr-machine-locked-v1');
    assert.strictEqual(machineLock.isEnabled(opts), true, 'a failed disable must not clear the enabled flag');
    // The correct fingerprint still recovers it.
    machineLock.disable(file, opts);
    assert.strictEqual(fs.readFileSync(file, 'utf8'), FAKE_AGE_KEY);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ─── resolveIdentity — the actual hook lib/crypto.js will call ─────────────

test('resolveIdentity is a no-op passthrough when not enabled', () => {
  const { dir, file } = tempIdentityFile();
  const opts = tempConfigOpts(dir);
  try {
    const r = machineLock.resolveIdentity(file, opts);
    assert.strictEqual(r.path, file);
    r.cleanup(); // must not throw
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveIdentity writes a single-use temp file with the unwrapped identity when enabled', () => {
  const { dir, file } = tempIdentityFile();
  const opts = tempConfigOpts(dir);
  try {
    machineLock.enable(file, opts);
    const r = machineLock.resolveIdentity(file, opts);
    assert.notStrictEqual(r.path, file, 'must be a different, temporary path');
    assert.strictEqual(fs.readFileSync(r.path, 'utf8'), FAKE_AGE_KEY);
    r.cleanup();
    assert.strictEqual(fs.existsSync(r.path), false, 'cleanup must remove the temp identity file');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveIdentity on a locked vault fails clearly when the fingerprint does not match — this IS the feature', () => {
  const { dir, file } = tempIdentityFile();
  const opts = tempConfigOpts(dir);
  try {
    machineLock.enable(file, opts);
    const otherMachineOpts = Object.assign({}, opts, { fingerprintOverride: 'a-completely-different-machine' });
    assert.throws(() => machineLock.resolveIdentity(file, otherMachineOpts), /machine-locked and will not decrypt here/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ─── status() ───────────────────────────────────────────────────────────────

test('status() reflects enabled/enabledAt and clears on disable', () => {
  const { dir, file } = tempIdentityFile();
  const opts = tempConfigOpts(dir);
  try {
    assert.strictEqual(machineLock.status(opts).enabled, false);
    machineLock.enable(file, opts);
    const s = machineLock.status(opts);
    assert.strictEqual(s.enabled, true);
    assert.ok(s.enabledAt);
    machineLock.disable(file, opts);
    assert.strictEqual(machineLock.status(opts).enabled, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('detectFingerprint returns a non-empty string on this real machine (sanity check)', () => {
  const fp = machineLock.detectFingerprint();
  assert.strictEqual(typeof fp, 'string');
  assert.ok(fp.length > 0);
  assert.ok(fp.includes(':'), 'fingerprint should be tagged with its source, e.g. "darwin:..." ');
});

console.log('machine-lock.test.js: ' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exit(1);
