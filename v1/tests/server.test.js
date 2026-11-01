'use strict';

// Integration test for the HTTP server — specifically the CORS allowlist and
// bearer-token auth middleware. Spins up the real Express app on an ephemeral
// port and sends real HTTP requests.

const assert = require('assert');
const http = require('http');
const { createApp } = require('../lib/server');

let passed = 0;
let failed = 0;

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => { passed++; })
    .catch((err) => {
      failed++;
      console.error('FAIL: ' + name);
      console.error('  ' + (err && err.message ? err.message : err));
    });
}

// Helper: start app on ephemeral port, return { port, close }
function listen(app) {
  return new Promise((resolve) => {
    const srv = app.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      resolve({ port, close: () => new Promise((r) => srv.close(r)) });
    });
  });
}

// Helper: make a request with optional Origin header
function request(port, method, pathname, headers) {
  return new Promise((resolve) => {
    const req = http.request({
      host: '127.0.0.1', port, path: pathname, method,
      headers: headers || {},
    }, (res) => {
      let chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', (err) => resolve({ error: err }));
    req.end();
  });
}

async function run() {

  await test('saved-token rotation changes the running app bearer immediately', async () => {
    const store = require('../lib/store');
    const lock = require('../lib/lock');
    const oldToken = store.rotateDaemonToken();
    const srv = await listen(createApp({ token: oldToken, tokenSource: 'saved' }));
    try {
      const rotated = await postJson(srv.port, '/api/daemon-token/rotate', {}, { Authorization: 'Bearer ' + oldToken });
      assert.strictEqual(rotated.status, 200);
      const newToken = JSON.parse(rotated.body).token;
      const old = await request(srv.port, 'GET', '/api/stats', { Authorization: 'Bearer ' + oldToken });
      assert.strictEqual(old.status, 401, 'old saved token must stop working without restart');
      const fresh = await request(srv.port, 'GET', '/api/stats', { Authorization: 'Bearer ' + newToken });
      assert.strictEqual(fresh.status, 200, 'new saved token works immediately');
      const revoked = await postJson(srv.port, '/api/daemon-token/revoke', {}, { Authorization: 'Bearer ' + newToken });
      assert.strictEqual(revoked.status, 200);
      const after = await request(srv.port, 'GET', '/api/stats', { Authorization: 'Bearer ' + newToken });
      assert.strictEqual(after.status, 401, 'revocation must keep the bearer gate closed');
      const noToken = await request(srv.port, 'GET', '/api/stats');
      assert.strictEqual(noToken.status, 401, 'revocation must not turn authentication off');
    } finally { await srv.close(); store.revokeDaemonToken(); lock._resetRateLimiter(); }
  });

  await test('saved-token file revocation invalidates the running app', async () => {
    const store = require('../lib/store');
    const lock = require('../lib/lock');
    const oldToken = store.rotateDaemonToken();
    const srv = await listen(createApp({ token: oldToken, tokenSource: 'saved' }));
    try {
      store.revokeDaemonToken();
      const blocked = await request(srv.port, 'GET', '/api/stats', { Authorization: 'Bearer ' + oldToken });
      assert.strictEqual(blocked.status, 401, 'local revocation must also take effect immediately');
    } finally { await srv.close(); store.revokeDaemonToken(); lock._resetRateLimiter(); }
  });

  await test('explicit bearer remains stable when the saved token changes', async () => {
    const store = require('../lib/store');
    const lock = require('../lib/lock');
    const srv = await listen(createApp({ token: 'explicit-test-bearer' }));
    try {
      store.rotateDaemonToken(); store.revokeDaemonToken();
      const allowed = await request(srv.port, 'GET', '/api/stats', { Authorization: 'Bearer explicit-test-bearer' });
      assert.strictEqual(allowed.status, 200);
    } finally { await srv.close(); store.revokeDaemonToken(); lock._resetRateLimiter(); }
  });

  await test('loopback API refuses a remote Host used for DNS rebinding', async () => {
    const store = require('../lib/store');
    const name = '_HOST_GUARD_' + Date.now();
    store.set(name, 'synthetic-host-guard-value');
    const srv = await listen(createApp({}));
    try {
      const blocked = await request(srv.port, 'GET', '/api/credentials/' + name + '/value', { Host: 'attacker.example' });
      assert.strictEqual(blocked.status, 403, 'untrusted Host must not read loopback values');
      assert.ok(blocked.headers['cache-control'].includes('no-store'));
      assert.ok(!blocked.body.includes('synthetic-host-guard-value'));
      const allowed = await request(srv.port, 'GET', '/api/credentials/' + name + '/value', { Host: 'localhost:' + srv.port });
      assert.strictEqual(allowed.status, 200);
    } finally { await srv.close(); store.remove(name); }
  });

  await test('bearer gate covers case-insensitive Express routes', async () => {
    const lock = require('../lib/lock');
    lock._resetRateLimiter();
    const srv = await listen(createApp({ token: 'route-test-token' }));
    try {
      const blocked = await request(srv.port, 'GET', '/API/stats');
      assert.strictEqual(blocked.status, 401, 'case variant must require bearer');
      const allowed = await request(srv.port, 'GET', '/API/stats', { Authorization: 'Bearer route-test-token' });
      assert.strictEqual(allowed.status, 200);
      const health = await request(srv.port, 'GET', '/API/health/');
      assert.strictEqual(health.status, 200, 'health remains public across route spellings');
    } finally { await srv.close(); lock._resetRateLimiter(); }
  });

  await test('PIN gate covers trailing-slash and case variants of value routes', async () => {
    const store = require('../lib/store');
    const lock = require('../lib/lock');
    const name = '_ROUTE_LOCK_' + Date.now();
    store.set(name, 'synthetic-route-value');
    lock.setPin('5931', '', {});
    const srv = await listen(createApp({}));
    try {
      for (const route of ['/api/credentials/' + name + '/value/', '/API/credentials/' + name + '/VALUE']) {
        const blocked = await request(srv.port, 'GET', route);
        assert.strictEqual(blocked.status, 401, 'route spelling must require unlock');
        assert.ok(!blocked.body.includes('synthetic-route-value'));
        const session = lock.createSession({});
        const allowed = await request(srv.port, 'GET', route, { 'X-Credmgr-Session': session });
        assert.strictEqual(allowed.status, 200);
        assert.strictEqual(JSON.parse(allowed.body).value, 'synthetic-route-value');
      }
      const head = await request(srv.port, 'HEAD', '/api/credentials/' + name + '/value');
      assert.strictEqual(head.status, 401, 'HEAD must not expose a hash or length of a locked value');
    } finally {
      await srv.close(); lock.removePin('5931', {}); lock.revokeAllSessions(); store.remove(name);
    }
  });

  await test('export-password gate covers case variants of export routes', async () => {
    const lock = require('../lib/lock');
    lock.setExportPassword('route-export-password', '', {});
    const srv = await listen(createApp({}));
    try {
      const blocked = await request(srv.port, 'GET', '/API/EXPORT/global');
      assert.strictEqual(blocked.status, 401, 'case variant must require export password');
      const head = await request(srv.port, 'HEAD', '/api/export/global');
      assert.strictEqual(head.status, 401, 'HEAD must require the export password too');
      const allowed = await request(srv.port, 'GET', '/API/EXPORT/global', { 'X-Credmgr-Export-Auth': 'route-export-password' });
      assert.strictEqual(allowed.status, 200);
    } finally { await srv.close(); lock.removeExportPassword('route-export-password', {}); lock._resetRateLimiter(); }
  });

  // ─── CORS: disabled by default ─────────────────────────────────────────

  await test('CORS disabled by default — no Access-Control-Allow-Origin header', async () => {
    const app = createApp({});
    const srv = await listen(app);
    try {
      const r = await request(srv.port, 'GET', '/api/health', { 'Origin': 'https://anywhere.com' });
      assert.strictEqual(r.status, 200);
      assert.strictEqual(r.headers['access-control-allow-origin'], undefined,
        'no CORS header when allowCors is not set');
    } finally { await srv.close(); }
  });

  // ─── CORS: allowCors:true uses localhost-only allowlist ────────────────

  await test('allowCors:true echoes localhost origins, rejects others', async () => {
    const app = createApp({ allowCors: true });
    const srv = await listen(app);
    try {
      const ok = await request(srv.port, 'OPTIONS', '/api/health', {
        'Origin': 'http://localhost:9876',
        'Access-Control-Request-Method': 'GET',
      });
      assert.strictEqual(ok.status, 204);
      assert.strictEqual(ok.headers['access-control-allow-origin'], 'http://localhost:9876');

      const evil = await request(srv.port, 'OPTIONS', '/api/health', {
        'Origin': 'https://evil.example.com',
        'Access-Control-Request-Method': 'GET',
      });
      assert.strictEqual(evil.status, 403);
      assert.strictEqual(evil.headers['access-control-allow-origin'], undefined);
    } finally { await srv.close(); }
  });

  // ─── CORS: explicit allowlist ──────────────────────────────────────────

  await test('allowCors:[origins] — exact-match allowlist only', async () => {
    const allowed = 'https://my-app.example.com';
    const app = createApp({ allowCors: [allowed] });
    const srv = await listen(app);
    try {
      const ok = await request(srv.port, 'OPTIONS', '/api/health', {
        'Origin': allowed, 'Access-Control-Request-Method': 'GET',
      });
      assert.strictEqual(ok.status, 204);
      assert.strictEqual(ok.headers['access-control-allow-origin'], allowed);

      // Subdomain spoofing attempt — must be rejected
      const spoofed = await request(srv.port, 'OPTIONS', '/api/health', {
        'Origin': 'https://evil.my-app.example.com',
        'Access-Control-Request-Method': 'GET',
      });
      assert.strictEqual(spoofed.status, 403);
      assert.strictEqual(spoofed.headers['access-control-allow-origin'], undefined);

      // 'null' origin (sandboxed iframe / file://) — must be rejected
      const nullOrigin = await request(srv.port, 'OPTIONS', '/api/health', {
        'Origin': 'null', 'Access-Control-Request-Method': 'GET',
      });
      assert.strictEqual(nullOrigin.status, 403);
    } finally { await srv.close(); }
  });

  // ─── Bearer token: required when configured ────────────────────────────

  await test('token:set — /api/* requires valid bearer, /api/health is public', async () => {
    const app = createApp({ token: 'secret-token-abc' });
    const srv = await listen(app);
    try {
      // /api/health is always public
      const health = await request(srv.port, 'GET', '/api/health');
      assert.strictEqual(health.status, 200);

      // /api/stats requires auth
      const unauth = await request(srv.port, 'GET', '/api/stats');
      assert.strictEqual(unauth.status, 401);

      // Wrong token
      const wrong = await request(srv.port, 'GET', '/api/stats',
        { 'Authorization': 'Bearer wrong-token' });
      assert.strictEqual(wrong.status, 401);

      // Correct token
      const right = await request(srv.port, 'GET', '/api/stats',
        { 'Authorization': 'Bearer secret-token-abc' });
      assert.strictEqual(right.status, 200);
    } finally { await srv.close(); }
  });

  // ─── Bearer token: constant-time comparison ────────────────────────────

  await test('token:set — length-mismatch tokens are rejected without crash', async () => {
    const app = createApp({ token: 'correct-token' });
    const srv = await listen(app);
    try {
      // Very short token (length mismatch must not cause timingSafeEqual throw)
      const r1 = await request(srv.port, 'GET', '/api/stats',
        { 'Authorization': 'Bearer x' });
      assert.strictEqual(r1.status, 401);

      // Very long token
      const r2 = await request(srv.port, 'GET', '/api/stats',
        { 'Authorization': 'Bearer ' + 'x'.repeat(1000) });
      assert.strictEqual(r2.status, 401);

      // Malformed header (no "Bearer " prefix)
      const r3 = await request(srv.port, 'GET', '/api/stats',
        { 'Authorization': 'correct-token' });
      assert.strictEqual(r3.status, 401);
    } finally { await srv.close(); }
  });

  // ─── New v1.2 endpoints ────────────────────────────────────────────────

  await test('GET /api/generate returns a secret of requested length/type', async () => {
    const app = createApp({});
    const srv = await listen(app);
    try {
      const r = await request(srv.port, 'GET', '/api/generate?length=40&type=hex');
      assert.strictEqual(r.status, 200);
      const body = JSON.parse(r.body);
      assert.strictEqual(body.value.length, 40);
      assert.ok(/^[0-9a-f]+$/.test(body.value), 'expected hex output');
    } finally { await srv.close(); }
  });

  await test('POST /api/doctor (dry run) returns integrity + heal report', async () => {
    const app = createApp({});
    const srv = await listen(app);
    try {
      const r = await new Promise((resolve) => {
        const req = http.request({
          host: '127.0.0.1', port: srv.port, path: '/api/doctor', method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        }, (res) => {
          let chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
        });
        req.end(JSON.stringify({ fix: false }));
      });
      assert.strictEqual(r.status, 200);
      const body = JSON.parse(r.body);
      assert.ok('integrity' in body && 'heal' in body);
      assert.strictEqual(body.heal.applied, false, 'dry run must not apply');
    } finally { await srv.close(); }
  });

  await test('GET /api/credentials/:name/history returns redacted rows', async () => {
    const store = require('../lib/store');
    const name = '_SRV_HIST_' + Date.now();
    store.set(name, 'v1');
    store.set(name, 'v2');
    const app = createApp({});
    const srv = await listen(app);
    try {
      const r = await request(srv.port, 'GET', '/api/credentials/' + name + '/history');
      assert.strictEqual(r.status, 200);
      const rows = JSON.parse(r.body);
      assert.ok(rows.length >= 1);
      assert.ok(rows.every((x) => x.newValue === null || x.newValue === '[redacted]'),
        'history over HTTP must never contain raw values');
    } finally {
      await srv.close();
      store.remove(name);
    }
  });

  await test('security headers present on every response', async () => {
    const app = createApp({});
    const srv = await listen(app);
    try {
      const r = await request(srv.port, 'GET', '/api/health');
      assert.ok(r.headers['content-security-policy'].includes("script-src 'self'"));
      assert.strictEqual(r.headers['x-frame-options'], 'DENY');
      assert.strictEqual(r.headers['x-content-type-options'], 'nosniff');
    } finally { await srv.close(); }
  });

  await test('POST /api/credentials/batch — wallet batch → one structured entry each', async () => {
    const store = require('../lib/store');
    const g = '_SRV_BATCH_' + Date.now();
    const app = createApp({});
    const srv = await listen(app);
    try {
      const body = JSON.stringify({ credentials: [
        { name: g + '_A', address: '0x' + 'a'.repeat(40), privateKey: '0x' + 'b'.repeat(64), seedPhrase: 'a b c d e f g h i j k l' },
        { name: g + '_B', value: 'flat-one' },
      ], batchGroup: g });
      const r = await new Promise((resolve) => {
        const req = http.request({
          host: '127.0.0.1', port: srv.port, path: '/api/credentials/batch', method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        }, (res) => {
          let c = []; res.on('data', (d) => c.push(d));
          res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(c).toString('utf8') }));
        });
        req.end(body);
      });
      assert.strictEqual(r.status, 200);
      const out = JSON.parse(r.body);
      assert.strictEqual(out.added, 2);
      assert.strictEqual(store.getMetadata(g + '_A').format, 'structured');
      assert.strictEqual(store.getMetadata(g + '_A').category, 'wallet');
    } finally {
      await srv.close();
      store.remove(g + '_A'); store.remove(g + '_B');
    }
  });

  // ─── Changelog value redaction (v1.8 / plan 3.6) ─────────────────────────

  await test('GET /api/changelog never contains raw values', async () => {
    const store = require('../lib/store');
    const name = '_SRV_CHLOG_' + Date.now();
    store.set(name, 'super-secret-value-abc123');
    const app = createApp({});
    const srv = await listen(app);
    try {
      const r = await request(srv.port, 'GET', '/api/changelog');
      assert.strictEqual(r.status, 200);
      assert.ok(!r.body.includes('super-secret-value-abc123'),
        'changelog response must not leak plaintext values');
      const rows = JSON.parse(r.body);
      const mine = rows.find((c) => c.credentialName === name);
      assert.ok(mine, 'the add is in the changelog');
      assert.strictEqual(mine.newValue, '[redacted]');
    } finally {
      await srv.close();
      store.remove(name);
    }
  });

  // ─── Vault lock (v1.8 / plan Phase 1) ────────────────────────────────────

  await test('vault lock lifecycle: gate 401s while locked, unlock session opens it', async () => {
    const store = require('../lib/store');
    const lock = require('../lib/lock');
    const name = '_SRV_LOCK_' + Date.now();
    store.set(name, 'lock-gated-value');
    const app = createApp({});
    const srv = await listen(app);
    try {
      // No PIN → value endpoint is open (backward compat)
      let r = await request(srv.port, 'GET', '/api/credentials/' + name + '/value');
      assert.strictEqual(r.status, 200, 'no PIN registered → open');

      // Register a PIN via the API
      r = await postJson(srv.port, '/api/pin', { pin: '2468' });
      assert.strictEqual(r.status, 200);
      const setBody = JSON.parse(r.body);
      assert.ok(setBody.session, 'setting a PIN hands back a session');

      // THE acceptance test of the phase: locked vault must 401 the value curl
      r = await request(srv.port, 'GET', '/api/credentials/' + name + '/value');
      assert.strictEqual(r.status, 401, 'locked vault must refuse value reads');
      assert.ok(JSON.parse(r.body).locked === true);

      // Metadata stays free while locked (list must render)
      r = await request(srv.port, 'GET', '/api/credentials/' + name);
      assert.strictEqual(r.status, 200, 'metadata stays readable while locked');
      r = await request(srv.port, 'GET', '/api/credentials');
      assert.strictEqual(r.status, 200);

      // Wrong PIN → 401
      r = await postJson(srv.port, '/api/unlock', { pin: '0000' });
      assert.strictEqual(r.status, 401);

      // Right PIN → session unlocks the gate
      r = await postJson(srv.port, '/api/unlock', { pin: '2468' });
      assert.strictEqual(r.status, 200);
      const session = JSON.parse(r.body).session;
      r = await request(srv.port, 'GET', '/api/credentials/' + name + '/value',
        { 'X-Credmgr-Session': session });
      assert.strictEqual(r.status, 200, 'unlocked session reads values');

      // Export + ref are gated too
      r = await request(srv.port, 'GET', '/api/export/global');
      assert.strictEqual(r.status, 401, 'export is gated while locked');

      // Lock revokes the session
      r = await postJson(srv.port, '/api/lock', {}, { 'X-Credmgr-Session': session });
      assert.strictEqual(r.status, 200);
      r = await request(srv.port, 'GET', '/api/credentials/' + name + '/value',
        { 'X-Credmgr-Session': session });
      assert.strictEqual(r.status, 401, 'revoked session is locked out again');

      // lock-status reflects state
      r = await request(srv.port, 'GET', '/api/lock-status');
      const status = JSON.parse(r.body);
      assert.strictEqual(status.pinSet, true);
      assert.strictEqual(status.locked, true);

      // Remove the PIN (requires current) → everything opens again
      r = await postJson(srv.port, '/api/pin', { remove: true, currentPin: '2468' });
      assert.strictEqual(r.status, 200);
      r = await request(srv.port, 'GET', '/api/credentials/' + name + '/value');
      assert.strictEqual(r.status, 200, 'PIN removed → open again');
    } finally {
      await srv.close();
      const lockCleanup = require('../lib/lock');
      try { lockCleanup.removePin('2468', {}); } catch (_) { /* already removed */ }
      lockCleanup._resetRateLimiter();
      lock.revokeAllSessions();
      store.remove(name);
    }
  });

  await test('machine-lock: enable/status/disable over HTTP, with real round-trip verification', async () => {
    const cryptoLib = require('../lib/crypto');
    const machineLock = require('../lib/machine-lock');
    const app = createApp({});
    const srv = await listen(app);
    try {
      let r = await request(srv.port, 'GET', '/api/machine-lock');
      assert.strictEqual(r.status, 200);
      assert.strictEqual(JSON.parse(r.body).enabled, false);

      r = await postJson(srv.port, '/api/machine-lock/enable', {});
      assert.strictEqual(r.status, 200);
      assert.strictEqual(JSON.parse(r.body).enabled, true);

      r = await request(srv.port, 'GET', '/api/machine-lock');
      assert.strictEqual(JSON.parse(r.body).enabled, true);

      // Enabling twice is rejected, not silently accepted.
      r = await postJson(srv.port, '/api/machine-lock/enable', {});
      assert.strictEqual(r.status, 400);

      // The vault is still fully usable through the normal API while locked
      // (same machine) — export a value through the real HTTP surface.
      const name = '_SRV_MLOCK_' + Date.now();
      const store = require('../lib/store');
      store.set(name, 'machine-locked-http-value', { project: 'global' });
      r = await request(srv.port, 'GET', '/api/credentials/' + name + '/value');
      assert.strictEqual(r.status, 200);
      assert.strictEqual(JSON.parse(r.body).value, 'machine-locked-http-value');
      store.remove(name);

      r = await postJson(srv.port, '/api/machine-lock/disable', {});
      assert.strictEqual(r.status, 200);
      assert.strictEqual(JSON.parse(r.body).enabled, false);

      r = await request(srv.port, 'GET', '/api/machine-lock');
      assert.strictEqual(JSON.parse(r.body).enabled, false);
    } finally {
      // Belt-and-suspenders: never leave this sandbox's real identity locked
      // even if an assertion above threw before the disable call ran.
      try {
        if (machineLock.isEnabled({})) machineLock.disable(cryptoLib.getIdentityPath({}), {});
      } catch (_) { /* already disabled */ }
      await srv.close();
    }
  });

  await test('export password gates /api/export/:project (no daemon token in play)', async () => {
    const store = require('../lib/store');
    const lock = require('../lib/lock');
    const name = '_SRV_EXPORTPW_' + Date.now();
    store.set(name, 'export-gated-value', { project: 'global' });
    lock.setExportPassword('very-secret-export-pw', '', {});
    const app = createApp({});
    const srv = await listen(app);
    try {
      // No header at all → 401.
      let r = await request(srv.port, 'GET', '/api/export/global');
      assert.strictEqual(r.status, 401);
      assert.strictEqual(JSON.parse(r.body).exportLocked, true);

      // Wrong password → still 401.
      r = await request(srv.port, 'GET', '/api/export/global', { 'X-Credmgr-Export-Auth': 'nope' });
      assert.strictEqual(r.status, 401);

      // Correct export password → 200, and the export actually contains the value.
      r = await request(srv.port, 'GET', '/api/export/global', { 'X-Credmgr-Export-Auth': 'very-secret-export-pw' });
      assert.strictEqual(r.status, 200);
      assert.ok(r.body.includes('export-gated-value'));

      // Keyed backup is gated the same way; a plain backup (no key) is not.
      r = await postJson(srv.port, '/api/backup', { includeKey: true });
      assert.strictEqual(r.status, 401);
      r = await postJson(srv.port, '/api/backup', { includeKey: true },
        { 'X-Credmgr-Export-Auth': 'very-secret-export-pw' });
      assert.strictEqual(r.status, 200);
    } finally {
      await srv.close();
      lock.removeExportPassword('very-secret-export-pw', {});
      lock._resetRateLimiter();
      store.remove(name);
    }
  });

  await test('export password gate has no bypass for an agent bearer token', async () => {
    const store = require('../lib/store');
    const lock = require('../lib/lock');
    const name = '_SRV_EXPORTPW2_' + Date.now();
    store.set(name, 'export-gated-value-2', { project: 'global' });
    lock.setExportPassword('another-export-pw', '', {});
    const app = createApp({ token: 'export-agent-token' });
    const srv = await listen(app);
    try {
      // A valid bearer token gets PAST the bearer gate (agent-authenticated)
      // but must NOT satisfy the export-password gate on its own — unlike
      // the PIN, this one has no agent bypass by design.
      let r = await request(srv.port, 'GET', '/api/export/global', { 'Authorization': 'Bearer export-agent-token' });
      assert.strictEqual(r.status, 401, 'bearer token alone must not satisfy the export-password gate');
      assert.strictEqual(JSON.parse(r.body).exportLocked, true);

      // Both the bearer token AND the export password together → 200.
      r = await request(srv.port, 'GET', '/api/export/global', {
        'Authorization': 'Bearer export-agent-token',
        'X-Credmgr-Export-Auth': 'another-export-pw',
      });
      assert.strictEqual(r.status, 200);
    } finally {
      await srv.close();
      lock.removeExportPassword('another-export-pw', {});
      lock._resetRateLimiter();
      store.remove(name);
    }
  });

  await test('DELETE /api/projects/:id removes an empty project, refuses a non-empty one', async () => {
    const store = require('../lib/store');
    const projectId = 'zz_test_http_teardown_' + Date.now();
    const name = '_SRV_PROJRM_' + Date.now();
    store.set(name, 'v', { project: projectId });
    const app = createApp({});
    const srv = await listen(app);
    try {
      let r = await request(srv.port, 'DELETE', '/api/projects/' + projectId);
      assert.strictEqual(r.status, 400, 'must refuse while a credential still references it');

      store.remove(name);
      r = await request(srv.port, 'DELETE', '/api/projects/' + projectId);
      assert.strictEqual(r.status, 200);
      assert.strictEqual(JSON.parse(r.body).removed, true);

      r = await request(srv.port, 'DELETE', '/api/projects/' + projectId);
      assert.strictEqual(r.status, 404, 'already gone — not found the second time');
    } finally {
      await srv.close();
      try { store.remove(name); } catch (_) { /* already removed */ }
    }
  });

  await test('AI integrations: create/list/toggle/remove over HTTP', async () => {
    const integrations = require('../lib/integrations');
    for (const i of integrations.list()) integrations.remove(i.id);
    const app = createApp({});
    const srv = await listen(app);
    try {
      // Note: `gated` is deliberately sticky per lib/integrations.js (once any
      // integration is ever created, it never un-gates) — other test files
      // sharing this sandbox (mcp-gate.test.js, integrations.test.js) may
      // have already flipped it, so this only asserts the LIST is empty, not
      // that gated:false — the sticky-on-creation behavior is asserted below.
      let r = await request(srv.port, 'GET', '/api/integrations');
      assert.strictEqual(r.status, 200);
      assert.deepStrictEqual(JSON.parse(r.body).integrations, []);

      r = await postJson(srv.port, '/api/integrations', { name: 'Claude', accountLabel: 'alice@example.com' });
      assert.strictEqual(r.status, 200);
      const created = JSON.parse(r.body);
      assert.ok(created.id);

      r = await request(srv.port, 'GET', '/api/integrations');
      let status = JSON.parse(r.body);
      assert.strictEqual(status.gated, true, 'creating an integration must leave the gate on');
      assert.strictEqual(status.integrations.length, 1);
      assert.strictEqual(status.integrations[0].enabled, true);
      assert.strictEqual(status.integrations[0].accountLabel, 'alice@example.com');

      r = await postJson(srv.port, '/api/integrations/' + created.id + '/toggle', { enabled: false });
      assert.strictEqual(r.status, 200);
      assert.strictEqual(JSON.parse(r.body).enabled, false);

      r = await request(srv.port, 'DELETE', '/api/integrations/' + created.id);
      assert.strictEqual(r.status, 200);
      assert.strictEqual(JSON.parse(r.body).removed, true);

      r = await request(srv.port, 'GET', '/api/integrations');
      status = JSON.parse(r.body);
      assert.deepStrictEqual(status.integrations, []);
      assert.strictEqual(status.gated, true, 'gate stays sticky even after the list is empty again');
    } finally {
      await srv.close();
      const integrations2 = require('../lib/integrations');
      for (const i of integrations2.list()) integrations2.remove(i.id);
    }
  });

  await test('POST /api/suggestions/dismiss persists across a fresh GET /api/suggestions scan', async () => {
    const store = require('../lib/store');
    const g = '_SRV_SUGG_' + Date.now();
    store.set(g + '_SVC_USER', 'someone@example.com');
    store.set(g + '_SVC_PASS', 'hunter2-hunter2');
    const app = createApp({});
    const srv = await listen(app);
    try {
      let r = await request(srv.port, 'GET', '/api/suggestions');
      assert.strictEqual(r.status, 200);
      const list = JSON.parse(r.body);
      const target = list.find((s) => s.names && s.names.includes(g + '_SVC_USER'));
      assert.ok(target, 'expected a merge-candidates suggestion over HTTP');
      assert.ok(target.key, 'suggestion carries a stable key over the wire');

      r = await postJson(srv.port, '/api/suggestions/dismiss', { key: target.key });
      assert.strictEqual(r.status, 200);
      assert.strictEqual(JSON.parse(r.body).dismissed, true);

      // A brand-new GET (fresh scan, no client memory at all) must not
      // resurrect it — this is the server-persisted-memory acceptance test.
      r = await request(srv.port, 'GET', '/api/suggestions');
      const after = JSON.parse(r.body);
      assert.ok(!after.some((s) => s.key === target.key), 'dismissed suggestion stays hidden');

      r = await request(srv.port, 'GET', '/api/suggestions/dismissed');
      assert.ok(JSON.parse(r.body).some((x) => x.key === target.key));

      r = await postJson(srv.port, '/api/suggestions/restore-all', {});
      assert.strictEqual(r.status, 200);
      assert.ok(JSON.parse(r.body).restored >= 1);

      r = await request(srv.port, 'GET', '/api/suggestions');
      assert.ok(JSON.parse(r.body).some((s) => s.key === target.key), 'restore-all brings it back');
    } finally {
      await srv.close();
      store.remove(g + '_SVC_USER');
      store.remove(g + '_SVC_PASS');
    }
  });

  await test('bearer-authenticated agent bypasses the PIN gate', async () => {
    const store = require('../lib/store');
    const lock = require('../lib/lock');
    const name = '_SRV_AGENT_' + Date.now();
    store.set(name, 'agent-visible');
    lock.setPin('1357', '', {});
    const app = createApp({ token: 'agent-token-xyz' });
    const srv = await listen(app);
    try {
      // Agent with bearer: PIN not required (two-audience model)
      const r = await request(srv.port, 'GET', '/api/credentials/' + name + '/value',
        { 'Authorization': 'Bearer agent-token-xyz' });
      assert.strictEqual(r.status, 200, 'bearer agent bypasses PIN gate');
    } finally {
      await srv.close();
      lock.removePin('1357', {});
      lock._resetRateLimiter();
      store.remove(name);
    }
  });

  await test('requirePinForAgents makes the bearer path PIN-gated too', async () => {
    const store = require('../lib/store');
    const lock = require('../lib/lock');
    const name = '_SRV_AGENT2_' + Date.now();
    store.set(name, 'one-gate');
    lock.setPin('8642', '', {});
    lock.updateConfig({ requirePinForAgents: true }, {});
    const app = createApp({ token: 'agent-token-abc' });
    const srv = await listen(app);
    try {
      let r = await request(srv.port, 'GET', '/api/credentials/' + name + '/value',
        { 'Authorization': 'Bearer agent-token-abc' });
      assert.strictEqual(r.status, 401, 'requirePinForAgents → bearer alone is not enough');

      // Bearer + unlock session passes
      r = await postJson(srv.port, '/api/unlock', { pin: '8642' },
        { 'Authorization': 'Bearer agent-token-abc' });
      assert.strictEqual(r.status, 200);
      const session = JSON.parse(r.body).session;
      r = await request(srv.port, 'GET', '/api/credentials/' + name + '/value',
        { 'Authorization': 'Bearer agent-token-abc', 'X-Credmgr-Session': session });
      assert.strictEqual(r.status, 200);
    } finally {
      await srv.close();
      lock.updateConfig({ requirePinForAgents: null }, {});
      lock.removePin('8642', {});
      lock._resetRateLimiter();
      store.remove(name);
    }
  });

  await test('lockTimeoutMinutes change requires auth once a PIN is set', async () => {
    const lock = require('../lib/lock');
    const app = createApp({});
    const srv = await listen(app);
    try {
      // No PIN → freely settable (nothing to protect yet)
      let r = await postJson(srv.port, '/api/pin', { lockTimeoutMinutes: 30 });
      assert.strictEqual(r.status, 200);

      lock.setPin('5511', '', {});
      // PIN set + no session/currentPin → refused
      r = await postJson(srv.port, '/api/pin', { lockTimeoutMinutes: 240 });
      assert.strictEqual(r.status, 401, 'unauthenticated TTL change must be refused');
      assert.strictEqual(lock.getSettings().lockTimeoutMinutes, 30, 'TTL unchanged');

      // With a valid session → allowed
      const unlock = await postJson(srv.port, '/api/unlock', { pin: '5511' });
      const session = JSON.parse(unlock.body).session;
      r = await postJson(srv.port, '/api/pin', { lockTimeoutMinutes: 5 }, { 'X-Credmgr-Session': session });
      assert.strictEqual(r.status, 200);
      assert.strictEqual(lock.getSettings().lockTimeoutMinutes, 5);

      // With currentPin instead of a session → also allowed
      r = await postJson(srv.port, '/api/pin', { lockTimeoutMinutes: 15, currentPin: '5511' });
      assert.strictEqual(r.status, 200);
      assert.strictEqual(lock.getSettings().lockTimeoutMinutes, 15);
    } finally {
      await srv.close();
      lock.removePin('5511', {});
      lock.setLockTimeout(lock.DEFAULT_TTL_MINUTES, {});
      lock._resetRateLimiter();
    }
  });

  await test('unlock attempts are rate-limited after 5 failures', async () => {
    const lock = require('../lib/lock');
    lock.setPin('7777', '', {});
    const app = createApp({});
    const srv = await listen(app);
    try {
      for (let i = 0; i < 5; i++) {
        await postJson(srv.port, '/api/unlock', { pin: 'wrong' });
      }
      const r = await postJson(srv.port, '/api/unlock', { pin: '7777' });
      assert.strictEqual(r.status, 429, 'blocked even with the right PIN during the delay');
      assert.ok(r.headers['retry-after'], 'Retry-After header present');
    } finally {
      await srv.close();
      lock._resetRateLimiter();
      lock.removePin('7777', {});
    }
  });

  // ─── Daemon-token hygiene (v1.8 / plan Phase 2) ──────────────────────────

  await test('GET /api/daemon-token returns last4 only; rotate reveals once', async () => {
    const store = require('../lib/store');
    const app = createApp({});
    const srv = await listen(app);
    try {
      const rot = await postJson(srv.port, '/api/daemon-token/rotate', {});
      assert.strictEqual(rot.status, 200);
      const fullToken = JSON.parse(rot.body).token;
      assert.ok(fullToken && fullToken.length >= 32, 'rotate returns the full token once');

      const r = await request(srv.port, 'GET', '/api/daemon-token');
      assert.strictEqual(r.status, 200);
      const body = JSON.parse(r.body);
      assert.strictEqual(body.hasToken, true);
      assert.strictEqual(body.last4, fullToken.slice(-4));
      assert.ok(!('token' in body), 'status endpoint must not carry the full token');
      assert.ok(!r.body.includes(fullToken), 'full token must not appear in status response');
    } finally {
      await srv.close();
      store.revokeDaemonToken();
    }
  });

  // ─── /api/status (v1.8 / plan 5.6) ───────────────────────────────────────

  await test('GET /api/status reports bind/tokenRequired/version/uptime', async () => {
    const app = createApp({ bind: '127.0.0.1' });
    const srv = await listen(app);
    try {
      const r = await request(srv.port, 'GET', '/api/status');
      assert.strictEqual(r.status, 200);
      const body = JSON.parse(r.body);
      assert.strictEqual(body.bind, '127.0.0.1');
      assert.strictEqual(body.tokenRequired, false);
      assert.ok(typeof body.version === 'string' && body.version.length > 0);
      assert.ok(body.uptimeSeconds >= 0);
    } finally { await srv.close(); }
  });

  console.log('server.test.js: ' + passed + ' passed, ' + failed + ' failed');
  if (failed > 0) process.exit(1);
}

// Helper: POST JSON with optional extra headers
function postJson(port, pathname, body, headers) {
  return new Promise((resolve) => {
    const payload = JSON.stringify(body || {});
    const req = http.request({
      host: '127.0.0.1', port, path: pathname, method: 'POST',
      headers: Object.assign({
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      }, headers || {}),
    }, (res) => {
      let chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', (err) => resolve({ error: err }));
    req.end(payload);
  });
}

run().catch((err) => {
  console.error('server.test.js CRASHED:', err);
  process.exit(1);
});
