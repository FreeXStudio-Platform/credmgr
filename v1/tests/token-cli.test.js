'use strict';

// Exercise token-source selection through the real CLI with the suite's
// CREDMGR_HOME. No default user token directory is read or written.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { execFileSync, spawn } = require('child_process');
const store = require('../lib/store');
let passed = 0;
let failed = 0;
const BIN = path.join(__dirname, '../bin/credmgr');

async function test(name, fn) {
  try { await fn(); passed++; }
  catch (err) { failed++; console.error('FAIL: ' + name + '\n  ' + err.message); }
}

function request(port, method, route, token) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: route,
      headers: { Authorization: 'Bearer ' + token } }, res => {
      let body = ''; res.on('data', data => body += data);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject); req.setTimeout(10000, () => req.destroy(new Error('CLI request timed out'))); req.end();
  });
}

function launch(args = [], tokenEnv = '') {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, 'daemon', '--port=0', ...args], {
      env: { ...process.env, CREDMGR_TOKEN: tokenEnv }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('CLI daemon did not become ready')); }, 10000);
    child.stdout.on('data', chunk => {
      output += chunk;
      const match = output.match(/http:\/\/127\.0\.0\.1:(\d+)/);
      if (match) {
        clearTimeout(timer);
        resolve({ port: Number(match[1]), close: () => new Promise(r => { child.once('exit', r); child.kill(); }) });
      }
    });
    child.stderr.resume();
    child.on('error', err => { clearTimeout(timer); reject(err); });
    child.on('exit', () => { clearTimeout(timer); if (!output.includes('running at')) reject(new Error('CLI daemon exited before ready')); });
  });
}

async function run() {
  assert.ok(process.env.CREDMGR_HOME, 'token CLI tests require the suite disposable vault');
  await test('CLI token commands share the CREDMGR_HOME-aware token path with HTTP', async () => {
    const selected = execFileSync(process.execPath, [BIN, 'token', 'path'], { encoding: 'utf8' }).trim();
    assert.strictEqual(selected, store.daemonTokenPath());
    const generated = execFileSync(process.execPath, [BIN, 'token', 'generate'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    assert.ok(generated === store.getDaemonToken(), 'CLI and store must use the same token file');
    execFileSync(process.execPath, [BIN, 'token', 'revoke'], { stdio: 'pipe' });
    assert.ok(!fs.existsSync(selected));
  });

  await test('running CLI daemon follows saved-token rotation and revocation', async () => {
    const oldToken = store.rotateDaemonToken();
    const srv = await launch();
    try {
      const first = await request(srv.port, 'GET', '/api/stats', oldToken);
      assert.strictEqual(first.status, 200);
      const rotated = await request(srv.port, 'POST', '/api/daemon-token/rotate', oldToken);
      assert.strictEqual(rotated.status, 200);
      const newToken = JSON.parse(rotated.body).token;
      assert.strictEqual((await request(srv.port, 'GET', '/api/stats', oldToken)).status, 401);
      assert.strictEqual((await request(srv.port, 'GET', '/api/stats', newToken)).status, 200);
      execFileSync(process.execPath, [BIN, 'token', 'revoke'], { stdio: 'pipe' });
      assert.strictEqual((await request(srv.port, 'GET', '/api/stats', newToken)).status, 401);
    } finally { await srv.close(); store.revokeDaemonToken(); }
  });

  await test('CLI and environment bearer overrides retain precedence and static semantics', async () => {
    store.rotateDaemonToken();
    for (const [args, env, expected] of [
      [[], 'environment-test-token', 'environment-test-token'],
      [['--token=flag-test-token'], 'environment-test-token', 'flag-test-token'],
    ]) {
      const srv = await launch(args, env);
      try {
        store.rotateDaemonToken(); store.revokeDaemonToken();
        assert.strictEqual((await request(srv.port, 'GET', '/api/stats', expected)).status, 200);
      } finally { await srv.close(); }
    }
  });
  store.revokeDaemonToken();
  console.log('token-cli.test.js: ' + passed + ' passed, ' + failed + ' failed');
  if (failed) process.exit(1);
}
run();
