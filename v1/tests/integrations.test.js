'use strict';

// Unit tests for lib/integrations.js — the AI-agent (Claude/ChatGPT/etc via
// `credmgr mcp`) connection registry: create/list/toggle/remove, and the
// opt-in-then-sticky gate model (isGated/isEnabled).

const assert = require('assert');
const fs = require('fs');
const integrations = require('../lib/integrations');

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

function cleanup() {
  for (const i of integrations.list()) integrations.remove(i.id);
  try { fs.unlinkSync(integrations.integrationsPath()); } catch (_) { /* already gone */ }
}

// ─── Fresh install: gate is off, everything backward-compatible ───────────

test('no integrations.json yet → not gated, list is empty', () => {
  cleanup();
  assert.strictEqual(integrations.isGated(), false);
  assert.deepStrictEqual(integrations.list(), []);
  assert.strictEqual(integrations.isEnabled('anything'), false);
});

// ─── Create / list / toggle / remove ───────────────────────────────────────

test('create requires a name', () => {
  cleanup();
  assert.throws(() => integrations.create({}), /needs a name/);
  assert.throws(() => integrations.create({ name: '   ' }), /needs a name/);
});

test('create → gates the install, appears in list, enabled by default', () => {
  cleanup();
  const created = integrations.create({ name: 'Claude', accountLabel: 'alice@example.com' });
  assert.ok(created.id);
  assert.strictEqual(created.name, 'Claude');
  assert.strictEqual(created.accountLabel, 'alice@example.com');

  assert.strictEqual(integrations.isGated(), true, 'creating the first integration flips the gate on');
  assert.strictEqual(integrations.isEnabled(created.id), true);

  const list = integrations.list();
  assert.strictEqual(list.length, 1);
  assert.strictEqual(list[0].id, created.id);
  assert.strictEqual(list[0].enabled, true);
  assert.strictEqual(list[0].lastUsedAt, null);
});

test('accountLabel is optional', () => {
  cleanup();
  const created = integrations.create({ name: 'ChatGPT' });
  assert.strictEqual(created.accountLabel, null);
});

test('setEnabled toggles without deleting; unknown id throws', () => {
  cleanup();
  const created = integrations.create({ name: 'Claude' });
  const off = integrations.setEnabled(created.id, false);
  assert.strictEqual(off.enabled, false);
  assert.strictEqual(integrations.isEnabled(created.id), false);
  assert.strictEqual(integrations.list().length, 1, 'toggling off does not remove the record');

  const on = integrations.setEnabled(created.id, true);
  assert.strictEqual(on.enabled, true);
  assert.strictEqual(integrations.isEnabled(created.id), true);

  assert.throws(() => integrations.setEnabled('nope', true), /not found/);
});

test('remove deletes the record but the gate stays engaged (no re-open-by-deleting)', () => {
  cleanup();
  const created = integrations.create({ name: 'Claude' });
  assert.strictEqual(integrations.isGated(), true);
  const r = integrations.remove(created.id);
  assert.strictEqual(r.removed, true);
  assert.strictEqual(integrations.list().length, 0);
  // The gate was flipped by ever creating one — deleting the only entry
  // must NOT silently reopen full access to every unlisted MCP client.
  assert.strictEqual(integrations.isGated(), true, 'gate stays sticky after deleting the last integration');
  assert.strictEqual(integrations.isEnabled(created.id), false, 'and the deleted id is no longer enabled');
});

test('recordUse stamps lastUsedAt; no-ops for unknown/missing id', () => {
  cleanup();
  const created = integrations.create({ name: 'Claude' });
  assert.strictEqual(integrations.list()[0].lastUsedAt, null);
  integrations.recordUse(created.id);
  const after = integrations.list().find((i) => i.id === created.id);
  assert.ok(after.lastUsedAt, 'lastUsedAt should be stamped after recordUse');
  // No-throw for garbage input — this is called unconditionally by mcp/server.js.
  integrations.recordUse(null);
  integrations.recordUse('does-not-exist');
});

test('credentials at rest never carry a usable secret — id is a public handle, not a token', () => {
  cleanup();
  integrations.create({ name: 'Claude', accountLabel: 'ops@example.com' });
  const raw = fs.readFileSync(integrations.integrationsPath(), 'utf8');
  // The file is metadata by design (mirrors index.json) — assert only that
  // no separate secret material was introduced (there is no token field).
  assert.ok(!raw.includes('"token"'), 'integrations.json must not carry a token field');
});

cleanup();
console.log('integrations.test.js: ' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exit(1);
