'use strict';

/**
 * credmgr — public Node.js API
 *
 * This is the "library mode" entry point. Other Node.js projects can import
 * credmgr directly to read/write credentials without spawning the CLI or
 * running the HTTP daemon.
 *
 *   const credmgr = require('credmgr');
 *   const key = await credmgr.get('ACME_API_KEY');
 *
 * Four integration modes exist (see docs/INTEGRATION.md for the full guide):
 *
 *   1. Library      — require('credmgr').get(name)        (this file)
 *   2. HTTP daemon  — credmgr daemon + Client()            (./client/index.js)
 *   3. CLI          — child_process.spawn 'credmgr'        (./bin/credmgr)
 *   4. MCP server   — credmgr mcp (for AI agents)          (./mcp/server.js)
 *
 * All four modes share the same underlying store (./lib/store.js), so any
 * credential written by one mode is immediately readable by the others.
 */

const store = require('./lib/store');
const { classify } = require('./lib/classify');

// ─── Read ───────────────────────────────────────────────────────────────

/**
 * Read a credential's plaintext value.
 * @param {string} name — the credential name (e.g. 'ACME_API_KEY')
 * @param {object} [opts]
 * @param {string} [opts.source='library'] — tag access log entries (e.g. 'agent:claude')
 * @returns {Promise<string|null>} the decrypted value (or null if not found)
 */
async function get(name, opts = {}) {
  const source = opts.source || 'library';
  const result = store.get(name, opts, source);
  if (!result) return null;
  return result.value;
}

/**
 * Like `get()` but returns `{ value, metadata }` so callers can read both
 * the plaintext value and the credential's metadata (ref, project, tags…)
 * in a single call.
 */
async function getWithMetadata(name, opts = {}) {
  const source = opts.source || 'library';
  return store.get(name, opts, source);
}

/**
 * Get a credential's metadata (no plaintext value).
 */
function getMetadata(name) {
  return store.getMetadata(name);
}

/**
 * Read a credential by its ref number (e.g. 4821).
 * @returns {Promise<{value: string, metadata: object}|null>}
 */
async function getByRef(ref, opts = {}) {
  const source = opts.source || 'library';
  return store.getByRef(ref, opts, source);
}

// ─── Write ──────────────────────────────────────────────────────────────

/**
 * Create or overwrite a credential.
 */
function set(name, value, metaOverrides = {}) {
  return store.set(name, value, metaOverrides);
}

/**
 * Rotate a credential's value (tracks history in changelog).
 */
function rotate(name, newValue) {
  return store.rotate(name, newValue);
}

/**
 * Soft-delete a credential (recoverable via changelog for 7 days).
 */
function remove(name) {
  return store.remove(name);
}

// ─── Undo / history ─────────────────────────────────────────────────────

/**
 * Full change history for one credential, newest first. Values redacted
 * unless opts.includeValues — callers that need raw history content are
 * expected to be humans via the CLI/dashboard, not agents.
 */
function history(name, opts = {}) {
  return store.history(name, opts);
}

/**
 * Undo a specific change by its changelog id.
 * @param {string} changeId
 * @param {'replace'|'keep-both'} [mode='replace'] — 'replace' overwrites the
 *   current value with the historical one; 'keep-both' restores the
 *   historical value as a new "<name> old" credential and leaves the
 *   current one untouched (for when a name got reused after a mistaken
 *   delete and both the old and new secrets are actually needed).
 */
function undo(changeId, mode, opts = {}) {
  const changelog = require('./lib/changelog');
  return changelog.undo(changeId, opts, { mode: mode || 'replace' });
}

/**
 * Redacted 7-day change feed — changeId/action/credentialName/timestamp/actor
 * only, never previousValue/newValue. This is deliberately the ONLY view of
 * the changelog considered safe to expose to an AI agent: it lets an agent
 * notice "this credential was deleted/modified recently" and call undo()
 * with the changeId, without ever reading a secret's before/after value.
 * @param {string} [nameFilter] — restrict to one credential name
 */
function recentChanges(nameFilter, opts = {}) {
  const changelog = require('./lib/changelog');
  const all = changelog.listChanges(opts);
  const rows = nameFilter ? all.filter(c => c.credentialName === nameFilter) : all;
  return rows.map(c => ({
    changeId: c.changeId,
    timestamp: c.timestamp,
    action: c.action,
    credentialName: c.credentialName,
    actor: c.actor,
  }));
}

// ─── Discovery ──────────────────────────────────────────────────────────

function list(filters = {}) {
  return store.list(filters);
}

function search(query) {
  return store.search(query);
}

function listProjects() {
  return store.listProjects();
}

// ─── Bulk operations ────────────────────────────────────────────────────

function exportEnv(projectId) {
  return store.exportEnv(projectId);
}

/**
 * Get all credentials matching a filter as a plain `{ NAME: value }` object.
 * Convenience for child-process env-var injection.
 *
 * WARNING: this decrypts every matching credential at once. Only use for
 * narrow filters (e.g. a single project) and never log the result.
 */
async function getEnvObject(filters, opts = {}) {
  const items = store.list(filters || {});
  const source = opts.source || 'library';
  const out = {};
  for (const item of items) {
    try {
      const result = await store.get(item.name, opts, source);
      if (result) Object.defineProperty(out, item.name, {
        value: result.value, enumerable: true, writable: true, configurable: true,
      });
    } catch {
      // skip unreadable entries
    }
  }
  return out;
}

// ─── Admin ──────────────────────────────────────────────────────────────

function stats() {
  return store.stats();
}

function verifyIntegrity() {
  return store.verifyIntegrity();
}

function logAccess(credName, source) {
  return store.logAccess(credName, source);
}

function getAccessLog(filters) {
  return store.getAccessLog(filters);
}

// ─── Exports ────────────────────────────────────────────────────────────

module.exports = {
  // read
  get,
  getWithMetadata,
  getMetadata,
  getByRef,
  getEnvObject,
  // write
  set,
  rotate,
  remove,
  // undo / history
  history,
  undo,
  recentChanges,
  // discovery
  list,
  search,
  listProjects,
  exportEnv,
  // admin
  stats,
  verifyIntegrity,
  logAccess,
  getAccessLog,
  // low-level (for advanced consumers that need direct store access)
  store,
  classify,
};
