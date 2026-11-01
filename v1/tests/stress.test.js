'use strict';

// Bounded stress checks using the suite's disposable CREDMGR_HOME. Counts are
// intentionally small enough for normal development; this is not a load SLA.
const assert = require('assert');
const fs = require('fs');
const http = require('http');
const nodeCrypto = require('crypto');
const cryptoLib = require('../lib/crypto');
const store = require('../lib/store');
const lock = require('../lib/lock');
const { createApp } = require('../lib/server');
let passed = 0;
let failed = 0;

async function test(name, fn) {
  try { await fn(); passed++; }
  catch (err) { failed++; console.error('FAIL: ' + name + '\n  ' + err.message); }
}

function request(port, method, pathname, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: pathname, headers }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString(), headers: res.headers }));
    });
    req.on('error', reject);
    req.setTimeout(10000, () => req.destroy(new Error('Stress request timed out')));
    req.end();
  });
}

async function run() {
  await test('256 KiB binary age round-trip and 16 altered ciphertext refusals', () => {
    const value = nodeCrypto.randomBytes(256 * 1024);
    const encrypted = cryptoLib.encrypt(value);
    assert.ok(value.equals(cryptoLib.decryptToBuffer(encrypted)));
    for (let i = 0; i < 16; i++) {
      const altered = Buffer.from(encrypted);
      const offset = Math.floor(altered.length / 2) + i * 71;
      altered[offset] = altered[offset] === 65 ? 66 : 65;
      assert.throws(() => cryptoLib.decryptToBuffer(altered), 'altered ciphertext must not decrypt');
    }
  });

  await test('256-record batch dry-run preserves index and encrypted vault bytes', () => {
    const beforeIndex = fs.readFileSync(store.INDEX_PATH);
    const beforeVault = fs.readFileSync(store.VAULT_PATH);
    const items = Array.from({ length: 256 }, (_, i) => ({ name: '_DRY_STRESS_' + i, value: 'synthetic-' + i }));
    const result = store.batchImport(items, { dryRun: true });
    assert.strictEqual(result.added, 256);
    assert.strictEqual(result.errors, 0);
    assert.ok(beforeIndex.equals(fs.readFileSync(store.INDEX_PATH)));
    assert.ok(beforeVault.equals(fs.readFileSync(store.VAULT_PATH)));
  });

  await test('64-record Unicode batch preserves values, unique refs and encrypted metadata separation', () => {
    const items = Array.from({ length: 64 }, (_, i) => ({
      name: '_BATCH_STRESS_' + i, project: 'global', value: 'synthetic-stress-' + i + '\n雪\0' + 'x'.repeat(128),
    }));
    try {
      const result = store.batchImport(items, {});
      assert.strictEqual(result.added, 64);
      assert.strictEqual(result.errors, 0);
      const refs = new Set();
      for (const item of items) {
        const actual = store.get(item.name, {});
        assert.ok(actual.value === item.value, 'batch value differs');
        refs.add(actual.metadata.ref);
      }
      assert.strictEqual(refs.size, 64);
      const metadata = fs.readFileSync(store.INDEX_PATH, 'utf8');
      assert.ok(!metadata.includes('synthetic-stress-'), 'values must not enter metadata');
      assert.strictEqual(store.verifyIntegrity({}).ok, true);
    } finally { for (const item of items) store.remove(item.name, {}); }
  });

  await test('64 concurrent GET/HEAD route variants stay locked after PIN/session rotation', async () => {
    const name = '_HTTP_STRESS';
    store.set(name, 'synthetic-http-stress-value', { project: 'global' }, {});
    lock.setPin('7395', '', {});
    const oldSession = lock.createSession({});
    lock.setPin('8526', '7395', {});
    const srv = createApp({}).listen(0, '127.0.0.1');
    await new Promise(resolve => srv.once('listening', resolve));
    try {
      const results = await Promise.all(Array.from({ length: 64 }, (_, i) => request(
        srv.address().port, i % 2 ? 'HEAD' : 'GET',
        (i % 3 ? '/API/CREDENTIALS/' : '/api/credentials/') + name + (i % 2 ? '/VALUE/' : '/value'),
        { 'X-Credmgr-Session': oldSession },
      )));
      assert.ok(results.every(r => r.status === 401), 'every old-session request must be refused');
      assert.ok(results.every(r => !r.body.includes('synthetic-http-stress-value')));
      const allowed = await request(srv.address().port, 'GET', '/api/credentials/' + name + '/value',
        { 'X-Credmgr-Session': lock.createSession({}) });
      assert.strictEqual(allowed.status, 200);
      assert.ok(JSON.parse(allowed.body).value === 'synthetic-http-stress-value');
    } finally {
      await new Promise(resolve => srv.close(resolve));
      lock.removePin('8526', {}); lock.revokeAllSessions(); store.remove(name, {});
    }
  });

  console.log('stress.test.js: ' + passed + ' passed, ' + failed + ' failed');
  if (failed) process.exit(1);
}
run();
