'use strict';

// End-to-end test of the credmgr MCP server's tool surface (mcp/server.js):
// full read/write/rotate/delete access is on by default (2026-08-04 — every
// agent, every project, no flag), --read-only is the opt-out, and the
// undo/history system stays agent-proof — redacted signals never leak a
// secret's value, and no tool ever wraps changelog.deleteEntry/purgeAll/
// forcePurge. Spawns the real MCP entry point over JSON-RPC/stdio, exactly
// as an MCP client would, so a bug in argv handling or tool wiring can't
// slip through the way a unit test of the underlying functions could miss.

const assert = require('assert');
const path = require('path');
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
      console.error('  ' + (err && err.stack ? err.stack : err));
    });
}

const MCP_ENTRY = path.join(__dirname, '..', 'mcp', 'server.js');

// The install-gate flag (integrations.js: gateEverEnabled) is sticky by
// design — once ANY test in this sandboxed CREDMGR_HOME creates an
// integration (mcp-gate.test.js does), it stays gated for the rest of the
// run regardless of cleanup. Rather than depend on test file ordering, every
// client here carries its own always-enabled integration id, exactly like
// mcp-gate.test.js's own "enabled path" case does — correct under a fresh
// (ungated) sandbox or an already-gated one.
let INTEGRATION_ID = null;
function ensureIntegration() {
  if (!INTEGRATION_ID) INTEGRATION_ID = integrations.create({ name: 'mcp-tools-test' }).id;
  return INTEGRATION_ID;
}

// Minimal JSON-RPC/stdio client for the real MCP process — line-delimited
// JSON in both directions, matching mcp/server.js's own framing.
function makeClient(args) {
  const fullArgs = ['--integration', ensureIntegration(), ...(args || [])];
  const child = spawn(process.execPath, [MCP_ENTRY, ...fullArgs], { stdio: ['pipe', 'pipe', 'pipe'] });
  let buf = '';
  let nextId = 1;
  const waiters = new Map();
  let stderr = '';
  child.stderr.on('data', (c) => { stderr += c.toString(); });
  child.stdout.on('data', (chunk) => {
    buf += chunk.toString();
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch (_) { continue; }
      if (msg && msg.id != null && waiters.has(msg.id)) {
        waiters.get(msg.id)(msg);
        waiters.delete(msg.id);
      }
    }
  });

  function rpc(method, params) {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      const timer = setTimeout(() => {
        if (waiters.has(id)) { waiters.delete(id); reject(new Error('timeout on ' + method + ' — stderr: ' + stderr)); }
      }, 5000);
      waiters.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params: params || {} }) + '\n');
    });
  }

  async function callTool(name, args2) {
    const r = await rpc('tools/call', { name, arguments: args2 || {} });
    if (r.error) throw new Error('RPC error calling ' + name + ': ' + JSON.stringify(r.error));
    return r.result;
  }

  function text(result) {
    return result.content && result.content[0] && result.content[0].text;
  }

  function close() {
    try { child.stdin.end(); } catch (_) { /* already gone */ }
    try { child.kill(); } catch (_) { /* already gone */ }
  }

  return { rpc, callTool, text, close };
}

async function toolNames(client) {
  await client.rpc('initialize', {});
  const r = await client.rpc('tools/list', {});
  return r.result.tools.map((t) => t.name);
}

async function run() {
  for (const i of integrations.list()) integrations.remove(i.id); // ensure ungated for these tests

  await test('default launch (no flags): full read+write+undo tool set is present', async () => {
    const c = makeClient([]);
    const names = await toolNames(c);
    for (const n of [
      'credmgr_get', 'credmgr_search', 'credmgr_list', 'credmgr_list_projects', 'credmgr_get_metadata',
      'credmgr_recent_changes', 'credmgr_set', 'credmgr_rotate', 'credmgr_remove', 'credmgr_undo',
    ]) {
      assert.ok(names.includes(n), 'missing tool: ' + n + ' — got: ' + names.join(','));
    }
    c.close();
  });

  await test('--read-only strips write tools (set/rotate/remove/undo) but keeps everything read-only, including recent_changes', async () => {
    const c = makeClient(['--read-only']);
    const names = await toolNames(c);
    for (const n of ['credmgr_set', 'credmgr_rotate', 'credmgr_remove', 'credmgr_undo']) {
      assert.ok(!names.includes(n), 'write tool present under --read-only: ' + n);
    }
    assert.ok(names.includes('credmgr_recent_changes'), 'recent_changes must stay available in read-only mode');
    assert.ok(names.includes('credmgr_get'));
    c.close();
  });

  await test('no tool ever exposes permanent-history-destroying operations (deleteEntry/purgeAll/forcePurge)', async () => {
    const c = makeClient([]);
    const names = await toolNames(c);
    const forbidden = [
      'credmgr_delete_entry', 'credmgr_purge', 'credmgr_purge_all', 'credmgr_force_purge',
      'credmgr_changelog_purge', 'credmgr_purge_changelog', 'credmgr_purge_history',
    ];
    for (const f of forbidden) assert.ok(!names.includes(f), 'forbidden tool exposed: ' + f);
    c.close();
  });

  await test('remove -> redacted signal on search/get_metadata/recent_changes (no value leak) -> undo replace restores it', async () => {
    const c = makeClient([]);
    await c.rpc('initialize', {});
    const name = 'MCP_TEST_REMOVE_UNDO_' + Date.now();

    await c.callTool('credmgr_set', { name, value: 'secret-v1' });
    const rmRes = await c.callTool('credmgr_remove', { name });
    assert.ok(!rmRes.isError, 'remove should succeed: ' + c.text(rmRes));

    // get on a removed credential must not error blindly — it should explain, without leaking the value
    const getGone = await c.callTool('credmgr_get', { name });
    assert.ok(getGone.isError);
    assert.ok(!/secret-v1/.test(c.text(getGone)), 'must never leak the value in the not-found hint');
    assert.ok(/changeId/.test(c.text(getGone)) || /credmgr_undo/.test(c.text(getGone)), 'hint should point at undo');

    // get_metadata should surface a redacted ghost stub with recentChange, no value fields anywhere
    const metaRes = await c.callTool('credmgr_get_metadata', { name });
    const metaText = c.text(metaRes);
    assert.ok(!/secret-v1/.test(metaText), 'must never leak the value');
    assert.ok(!/previousValue|newValue/i.test(metaText), 'must never expose raw changelog value fields');
    const meta = JSON.parse(metaText);
    assert.strictEqual(meta.live, false);
    assert.ok(meta.recentChange && meta.recentChange.action === 'delete', 'recentChange should report the delete');
    const changeId = meta.recentChange.changeId;

    // search should also surface a ghost stub, still no value leak
    const searchRes = await c.callTool('credmgr_search', { query: name });
    const searchText = c.text(searchRes);
    assert.ok(!/secret-v1/.test(searchText));
    const searchItems = JSON.parse(searchText);
    assert.ok(searchItems.some((i) => i.name === name && i.live === false), 'search must surface the deleted ghost');

    // recent_changes: redacted, no value leak
    const rcRes = await c.callTool('credmgr_recent_changes', { name });
    const rcText = c.text(rcRes);
    assert.ok(!/secret-v1/.test(rcText));
    assert.ok(!/previousValue|newValue/i.test(rcText));

    // undo (replace, default) restores it
    const undoRes = await c.callTool('credmgr_undo', { changeId });
    assert.ok(!undoRes.isError, 'undo should succeed: ' + c.text(undoRes));

    const getBack = await c.callTool('credmgr_get', { name });
    assert.strictEqual(c.text(getBack), 'secret-v1');

    c.close();
  });

  await test('keep-both undo on a name-reuse collision: both the mistakenly-deleted and the new credential survive', async () => {
    const c = makeClient([]);
    await c.rpc('initialize', {});
    const name = 'MCP_TEST_KEEPBOTH_' + Date.now();

    await c.callTool('credmgr_set', { name, value: 'original-secret' });
    await c.callTool('credmgr_remove', { name });

    const metaRes = await c.callTool('credmgr_get_metadata', { name });
    const meta = JSON.parse(c.text(metaRes));
    const changeId = meta.recentChange.changeId;

    // mistakenly reuse the name for a different secret
    await c.callTool('credmgr_set', { name, value: 'new-secret' });

    // plain undo (replace) must refuse — there's a collision now
    const refused = await c.callTool('credmgr_undo', { changeId });
    assert.ok(refused.isError, 'replace-mode undo must refuse on a live collision');

    // keep-both restores the old one alongside the new one
    const undoRes = await c.callTool('credmgr_undo', { changeId, mode: 'keep-both' });
    assert.ok(!undoRes.isError, 'keep-both undo should succeed: ' + c.text(undoRes));

    const current = await c.callTool('credmgr_get', { name });
    assert.strictEqual(c.text(current), 'new-secret', 'current value must survive untouched');

    const old = await c.callTool('credmgr_get', { name: name + ' old' });
    assert.strictEqual(c.text(old), 'original-secret', 'old value must be recoverable alongside the new one');

    c.close();
  });

  for (const i of integrations.list()) integrations.remove(i.id);
  console.log('mcp-tools.test.js: ' + passed + ' passed, ' + failed + ' failed');
  if (failed > 0) process.exit(1);
}

run();
