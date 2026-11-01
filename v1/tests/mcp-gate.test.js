'use strict';

// End-to-end test of the actual enforcement point for AI-agent integrations:
// `mcp/server.js` refuses to start when the install is gated and the
// presented --integration id isn't enabled, and behaves normally otherwise.
// Unlike integrations.test.js (unit tests on the registry) or the server.js
// HTTP tests (registry management), this spawns the real MCP entry point as
// a subprocess — exactly how an AI client would launch it — so a bug in how
// mcp/server.js reads process.argv or calls the gate can't slip through.

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const integrations = require('../lib/integrations');

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

const MCP_ENTRY = path.join(__dirname, '..', 'mcp', 'server.js');

// Spawns the real MCP server, sends one JSON-RPC `initialize`, and resolves
// with how it behaved — never rejects, so a hang/crash is a normal result
// the assertions can inspect instead of a flaky test failure.
function runMcp(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [MCP_ENTRY, ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.stderr.on('data', (c) => { stderr += c.toString(); });
    child.on('exit', (code) => finish({ exited: true, code, stdout, stderr }));
    child.on('error', (err) => finish({ exited: true, code: null, stdout, stderr, spawnError: err }));

    // Give it a moment to either refuse (exit) or come up; if it's still
    // running, it means the gate let it through — probe with `initialize`.
    const timer = setTimeout(() => {
      try {
        child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }) + '\n');
      } catch (_) { /* already exited */ }
      setTimeout(() => {
        try { child.kill(); } catch (_) { /* already gone */ }
        finish({ exited: false, code: null, stdout, stderr });
      }, 300);
    }, 300);
  });
}

async function run() {
  for (const i of integrations.list()) integrations.remove(i.id);

  await test('ungated install (fresh, never used the feature): mcp starts with no --integration flag', async () => {
    const r = await runMcp([]);
    assert.ok(!r.exited || r.code === 0, 'should not refuse when never gated: ' + JSON.stringify(r));
    assert.ok(r.stdout.includes('"serverInfo"'), 'should have answered initialize: ' + JSON.stringify(r));
  });

  await test('gated install: unknown/missing --integration is refused with a clear stderr message', async () => {
    integrations.create({ name: 'Claude' }); // flips the gate on for this sandbox
    let r = await runMcp([]);
    assert.strictEqual(r.exited, true, 'no --integration at all should refuse to start: ' + JSON.stringify(r));
    assert.strictEqual(r.code, 1);
    assert.ok(r.stderr.includes('not enabled'), 'stderr should explain why: ' + r.stderr);
    assert.ok(!r.stdout.includes('"serverInfo"'), 'must not have served initialize');

    r = await runMcp(['--integration', 'not-a-real-id']);
    assert.strictEqual(r.exited, true, 'unknown id should refuse: ' + JSON.stringify(r));
    assert.strictEqual(r.code, 1);
  });

  await test('gated install: enabled --integration id is allowed through and stamps lastUsedAt', async () => {
    for (const i of integrations.list()) integrations.remove(i.id);
    const created = integrations.create({ name: 'ChatGPT' });
    const r = await runMcp(['--integration', created.id]);
    assert.ok(!r.exited || r.code === 0, 'enabled integration should be allowed: ' + JSON.stringify(r));
    assert.ok(r.stdout.includes('"serverInfo"'), 'should have answered initialize: ' + JSON.stringify(r));

    const after = integrations.list().find((i) => i.id === created.id);
    assert.ok(after.lastUsedAt, 'launching with this id should stamp lastUsedAt');
  });

  await test('gated install: disabling an integration re-refuses it (the actual kill switch)', async () => {
    for (const i of integrations.list()) integrations.remove(i.id);
    const created = integrations.create({ name: 'Claude' });
    integrations.setEnabled(created.id, false);
    const r = await runMcp(['--integration', created.id]);
    assert.strictEqual(r.exited, true, 'disabled integration must be refused: ' + JSON.stringify(r));
    assert.strictEqual(r.code, 1);
  });

  for (const i of integrations.list()) integrations.remove(i.id);

  await test('damaged integration registry refuses MCP instead of reopening a fresh install', async () => {
    const registry = integrations.integrationsPath();
    const original = fs.readFileSync(registry);
    try {
      for (const invalid of ['{"gateEverEnabled":', '{}', JSON.stringify({ version: 1, gateEverEnabled: true, integrations: [{ id: 'invalid', enabled: 'false' }] })]) {
        fs.writeFileSync(registry, invalid);
        const result = await runMcp([]);
        assert.strictEqual(result.exited, true, 'damaged registry must refuse launch');
        assert.strictEqual(result.code, 1);
        assert.ok(!result.stdout.includes('"serverInfo"'));
      }
    } finally { fs.writeFileSync(registry, original); }
  });
  console.log('mcp-gate.test.js: ' + passed + ' passed, ' + failed + ' failed');
  if (failed > 0) process.exit(1);
}

run();
