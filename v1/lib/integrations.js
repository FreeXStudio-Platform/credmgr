'use strict';

// AI-agent integrations (Claude, ChatGPT, or any other MCP client) that may
// run `credmgr mcp`. This is the enable/disable gate for that surface —
// mcp/server.js is the actual enforcement point; this module is just the
// registry it checks.
//
// Deliberately NOT a credential/token system: MCP's stdio transport gives a
// spawned process no signal at all about which AI account is on the other
// end, so there is nothing here to cryptographically verify. `accountLabel`
// is bookkeeping the operator types in — a name to recognize the connection
// by, not proof of anything. "If the account changes, remove and reconnect"
// is enforced by NOT exposing an edit endpoint for it: the only way to
// change accountLabel is delete + create, which is exactly the intended
// re-registration flow.
//
// Backward-compatible by construction: a fresh/never-used install has no
// integrations.json, so isGated() is false and mcp/server.js behaves exactly
// as it always has (fully open, same as the local CLI's trust model). The
// FIRST integration ever created flips gateEverEnabled permanently — from
// that point on, every `credmgr mcp` launch must present an enabled
// --integration id or is refused. Deleting the entry that flipped it does
// not un-flip it: the gate stays engaged once the feature has been used, so
// deleting integrations narrows the allowlist rather than reopening access.

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const cryptoLib = require('./crypto');

function integrationsPath() {
  return path.join(cryptoLib.CREDMGR_DIR, 'integrations.json');
}

function loadAll() {
  let raw;
  try { raw = fs.readFileSync(integrationsPath(), 'utf8'); }
  catch (err) {
    if (err.code === 'ENOENT') return { version: 1, gateEverEnabled: false, integrations: [] };
    throw new Error('Cannot read integration registry; restore it before launching MCP');
  }
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || parsed.version !== 1 || typeof parsed.gateEverEnabled !== 'boolean' ||
        !Array.isArray(parsed.integrations) ||
        (!parsed.gateEverEnabled && parsed.integrations.length > 0) ||
        parsed.integrations.some(i => !i || typeof i.id !== 'string' || !i.id || typeof i.enabled !== 'boolean')) {
      throw new Error();
    }
    return parsed;
  } catch {
    throw new Error('Invalid integration registry; restore it before launching MCP');
  }
}

function saveAll(data) {
  fs.mkdirSync(path.dirname(integrationsPath()), { recursive: true, mode: 0o700 });
  fs.writeFileSync(integrationsPath(), JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
}

function shortId() {
  return nodeCrypto.randomBytes(4).toString('hex');
}

/** Public list — never exposes anything beyond display metadata. */
function list() {
  return loadAll().integrations.map((i) => ({
    id: i.id,
    name: i.name,
    accountLabel: i.accountLabel,
    enabled: i.enabled,
    createdAt: i.createdAt,
    lastUsedAt: i.lastUsedAt || null,
  }));
}

/**
 * list() plus the gate flag — a UI showing just the list can't otherwise
 * tell "never used, still fully open" apart from "used before, everything
 * since deleted, now fully locked out" — both render as an empty list, but
 * they are opposite security states (see isGated's stickiness above).
 */
function status() {
  const data = loadAll();
  return { gated: data.gateEverEnabled === true, integrations: list() };
}

function create({ name, accountLabel }) {
  if (!name || typeof name !== 'string' || !name.trim()) {
    throw new Error('Integration needs a name (e.g. "Claude", "ChatGPT")');
  }
  const data = loadAll();
  const entry = {
    id: shortId(),
    name: name.trim(),
    accountLabel: (accountLabel && String(accountLabel).trim()) || null,
    enabled: true,
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
  };
  data.integrations.push(entry);
  data.gateEverEnabled = true;
  saveAll(data);
  return { id: entry.id, name: entry.name, accountLabel: entry.accountLabel };
}

function setEnabled(id, enabled) {
  const data = loadAll();
  const entry = data.integrations.find((i) => i.id === id);
  if (!entry) throw new Error('Integration not found: ' + id);
  entry.enabled = !!enabled;
  saveAll(data);
  return { id, enabled: entry.enabled };
}

function remove(id) {
  const data = loadAll();
  const before = data.integrations.length;
  data.integrations = data.integrations.filter((i) => i.id !== id);
  saveAll(data);
  return { removed: data.integrations.length < before };
}

/** Has this install ever used the feature? Controls whether the gate applies at all. */
function isGated() {
  return loadAll().gateEverEnabled === true;
}

/** The actual enforcement check — called by mcp/server.js on every launch. */
function isEnabled(id) {
  if (!id) return false;
  const entry = loadAll().integrations.find((i) => i.id === id);
  return !!(entry && entry.enabled);
}

function recordUse(id) {
  if (!id) return;
  const data = loadAll();
  const entry = data.integrations.find((i) => i.id === id);
  if (!entry) return;
  entry.lastUsedAt = new Date().toISOString();
  saveAll(data);
}

module.exports = { list, status, create, setEnabled, remove, isGated, isEnabled, recordUse, integrationsPath };
