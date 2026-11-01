'use strict';

/**
 * credmgr MCP (Model Context Protocol) server
 * ----------------------------------------------------------------
 * Exposes credmgr as a tool for AI agents that speak MCP — Claude Code,
 * Cursor, Windsurf, and any other MCP-compatible client.
 *
 * Transport: JSON-RPC 2.0 over stdio (the MCP standard).
 * Spec:      https://modelcontextprotocol.io/specification/
 *
 * Tools exposed:
 *   - credmgr_get(name)             → returns the plaintext value
 *   - credmgr_search(query)         → returns matching credentials (metadata)
 *   - credmgr_list(filters)         → lists credentials by project/category
 *   - credmgr_list_projects()       → lists known projects
 *   - credmgr_get_metadata(name)    → metadata only (safe to surface)
 *   - credmgr_set(name, value, …)   → create or overwrite a credential
 *   - credmgr_rotate(name, value)   → rotate a credential's value
 *   - credmgr_remove(name)          → soft-delete (recoverable 7 days)
 *   - credmgr_undo(changeId, mode)  → undo a change; mode 'replace' (default)
 *                                      overwrites current with the historical
 *                                      value, 'keep-both' restores it as a new
 *                                      "<name> old" entry alongside the
 *                                      current one (for name-reuse collisions)
 *   - credmgr_recent_changes(name?) → redacted 7-day change feed (no values)
 *
 * ── Full read/write/rotate/delete access is ON BY DEFAULT (2026-08-04 —
 * operator directive: every agent, every project, no flag, no allowance
 * gate). Pass --read-only to a specific launch to restrict it to the 5
 * read-only tools instead — that is now the opt-OUT, not the opt-in.
 *
 * ── Undo/history is deliberately the ONLY safety net, and it is designed to
 * survive a misbehaving or compromised agent:
 *   - Every write (set/rotate/remove, and merge under the hood) already logs
 *     to the encrypted changelog automatically inside lib/store.js — there is
 *     no code path an agent can reach through this MCP server that writes to
 *     the vault WITHOUT also logging the change. Nothing here calls the
 *     vault/index files directly.
 *   - credmgr_undo exposes lib/changelog.js's undo(), including 'keep-both'
 *     mode, so a wrong delete/overwrite is always recoverable — even when a
 *     name got reused and both the old and new secret are actually needed.
 *   - credmgr_recent_changes and the `recentChange` annotations on
 *     search/list/get_metadata/get expose ONLY changeId/action/timestamp/
 *     actor — never previousValue/newValue. An agent can always tell "this
 *     was recently changed/deleted, here's the changeId" without ever being
 *     able to read what the value was before or after.
 *   - lib/changelog.js's deleteEntry() / purgeAll() / forcePurge() — the
 *     operations that would PERMANENTLY destroy history early — are
 *     INTENTIONALLY not wrapped by any tool below. Do not add one. Those
 *     stay human-only (CLI `credmgr changelog purge` / dashboard), so no
 *     agent, however it's launched or however many flags it's given, can
 *     ever shorten or erase the 7-day recovery window.
 *
 * Usage in an MCP client config (e.g. Claude Code ~/.claude.json):
 *
 *   {
 *     "mcpServers": {
 *       "credmgr": {
 *         "command": "credmgr",
 *         "args": ["mcp"]
 *       }
 *     }
 *   }
 */

const credmgr = require('..');
const integrations = require('../lib/integrations');

const PROTOCOL_VERSION = '2024-11-05';
const SERVER_NAME = 'credmgr';
const SERVER_VERSION = '1.0.0';

// ─── Argument parsing ──────────────────────────────────────────────────
const ARGV = process.argv.slice(2);
// Write access is on by default (2026-08-04). --allow-writes is still
// accepted (now a no-op) so existing configs that already pass it keep
// working unchanged. --read-only is the actual opt-out.
const READ_ONLY = ARGV.includes('--read-only');
const ALLOW_WRITES = !READ_ONLY;
const AGENT_TAG = (() => {
  const i = ARGV.indexOf('--source');
  return i >= 0 && ARGV[i + 1] ? ARGV[i + 1] : 'agent:mcp';
})();
const INTEGRATION_ID = (() => {
  const i = ARGV.indexOf('--integration');
  return i >= 0 && ARGV[i + 1] ? ARGV[i + 1] : null;
})();

// ─── Integration gate ──────────────────────────────────────────────────
// Off by default (isGated() is false until the dashboard's "Connect
// Claude/ChatGPT" flow has been used at least once) so this never breaks an
// existing setup that predates the feature. Once gated, every launch needs
// an enabled --integration id from that registry or is refused outright —
// this is the actual "AI apps are locked out unless explicitly allowed"
// enforcement point; the dashboard endpoints only manage the registry.
try {
  if (integrations.isGated() && !integrations.isEnabled(INTEGRATION_ID)) {
    process.stderr.write(
      'credmgr mcp: this integration is not enabled.\n' +
      'Connect it from the credmgr dashboard (Settings → AI Integrations) and\n' +
      'use the --integration id it gives you, or re-enable an existing one.\n'
    );
    process.exit(1);
  }
  if (INTEGRATION_ID) integrations.recordUse(INTEGRATION_ID);
} catch {
  process.stderr.write('credmgr mcp: cannot validate the integration registry; launch refused.\n');
  process.exit(1);
}

// ─── Tool catalogue ────────────────────────────────────────────────────

const READ_TOOLS = [
  {
    name: 'credmgr_get',
    description:
      'Read a credential by name and return its plaintext value. ' +
      'Use sparingly — only when the value is actually needed for the current task. ' +
      'Never include the returned value in chat output, logs, or commit messages.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Credential name (e.g. ACME_API_KEY)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'credmgr_search',
    description:
      'Search credentials by name, tag, description, or field. Returns metadata only — no plaintext values. ' +
      'Use this when you don\'t know the exact credential name.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Free-text search query' },
      },
      required: ['query'],
    },
  },
  {
    name: 'credmgr_list',
    description: 'List credentials (metadata only) filtered by project, category, tag, or sensitivity.',
    inputSchema: {
      type: 'object',
      properties: {
        project: { type: 'string' },
        category: { type: 'string' },
        tag: { type: 'string' },
        sensitivity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
      },
    },
  },
  {
    name: 'credmgr_list_projects',
    description: 'List all known projects. Use this to discover what project IDs exist.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'credmgr_get_metadata',
    description: 'Get metadata for a credential (project, category, tags, format, sensitivity) without reading its value.',
    inputSchema: {
      type: 'object',
      properties: { name: { type: 'string' } },
      required: ['name'],
    },
  },
  {
    name: 'credmgr_recent_changes',
    description:
      'Redacted 7-day change feed — changeId, action, credentialName, timestamp, actor. ' +
      'NEVER includes the before/after value of a secret. Use this when a credential looks wrong, ' +
      'missing, or unexpectedly different from what you remember — it tells you WHETHER something ' +
      'changed recently and gives you the changeId to pass to credmgr_undo, without ever showing you ' +
      'what the old or new value was. Omit "name" to see the whole recent feed.',
    inputSchema: {
      type: 'object',
      properties: { name: { type: 'string', description: 'Optional — restrict to one credential name' } },
    },
  },
];

const WRITE_TOOLS = [
  {
    name: 'credmgr_set',
    description:
      'Create or overwrite a credential. Only use when the user has explicitly instructed you to add/update a credential. ' +
      'Never auto-save values produced during a task — propose the change and let the user confirm.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string' },
        value: { type: 'string' },
        project: { type: 'string' },
        category: { type: 'string' },
        sensitivity: { type: 'string' },
        description: { type: 'string' },
        tags: { type: 'array', items: { type: 'string' } },
      },
      required: ['name', 'value'],
    },
  },
  {
    name: 'credmgr_rotate',
    description: 'Rotate an existing credential\'s value. Tracks history in the changelog.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string' },
        value: { type: 'string' },
      },
      required: ['name', 'value'],
    },
  },
  {
    name: 'credmgr_remove',
    description:
      'Soft-delete a credential. NOT permanent — it stays recoverable via credmgr_undo for 7 days ' +
      '(the encrypted changelog, which nothing here can shorten or erase). Still, only remove a ' +
      'credential when the user has explicitly asked for it.',
    inputSchema: {
      type: 'object',
      properties: { name: { type: 'string' } },
      required: ['name'],
    },
  },
  {
    name: 'credmgr_undo',
    description:
      'Undo a change by its changeId (from credmgr_recent_changes or the recentChange field on ' +
      'search/list/get_metadata/get results). mode "replace" (default) overwrites the CURRENT value ' +
      'with the historical one — use for a straightforward "that edit/rotate was wrong, put it back". ' +
      'mode "keep-both" restores the historical value as a NEW credential named "<name> old" and ' +
      'leaves the current one untouched — use when a name got reused (e.g. a credential was deleted, ' +
      'then a different secret was later created under the same name) and BOTH the old and the new ' +
      'value are actually needed, not just one overwriting the other. Undoing an "add" is refused by ' +
      'design (adds are permanent — use credmgr_remove to delete a credential explicitly instead).',
    inputSchema: {
      type: 'object',
      properties: {
        changeId: { type: 'string' },
        mode: { type: 'string', enum: ['replace', 'keep-both'], description: 'Default: replace' },
      },
      required: ['changeId'],
    },
  },
];

function currentTools() {
  return ALLOW_WRITES ? READ_TOOLS.concat(WRITE_TOOLS) : READ_TOOLS;
}

// ─── Redacted change signal ─────────────────────────────────────────────
// The only changelog content ever handed to an agent: changeId/action/
// timestamp/actor. Never previousValue/newValue — see the header comment
// for why that boundary is load-bearing, not incidental.

// Decrypts and reads the whole (auto-purged-to-7-days) changelog ONCE and
// returns a credentialName → latest redacted entry map. Callers that need to
// annotate many items (list/search) must load this once and reuse it —
// calling recentChanges() per item would mean re-decrypting the entire
// changelog once per credential.
function loadLatestChangeMap() {
  let all;
  try { all = credmgr.recentChanges(); } catch (_) { return new Map(); }
  const latestByName = new Map();
  for (const c of all) { // newest-first, so the first write per name wins
    if (!latestByName.has(c.credentialName)) latestByName.set(c.credentialName, c);
  }
  return latestByName;
}

function redactedChangeFor(credentialName, latestMap) {
  const latest = (latestMap || loadLatestChangeMap()).get(credentialName);
  if (!latest) return null;
  return { changeId: latest.changeId, action: latest.action, timestamp: latest.timestamp, actor: latest.actor };
}

function withRecentChange(item, latestMap) {
  const rc = redactedChangeFor(item.name, latestMap);
  return rc ? { ...item, recentChange: rc } : item;
}

// For a search query that returned no (or only partial) live matches: sweep
// the redacted change feed for names that look like they matched but no
// longer exist live, so "it's gone" is discoverable instead of silently
// looking like it never existed. Ghost stubs carry no value, ever.
function ghostMatches(query, liveNames, latestMap) {
  const q = String(query || '').toLowerCase();
  if (!q) return [];
  const ghosts = [];
  for (const [credentialName, latest] of latestMap) {
    if (liveNames.has(credentialName)) continue; // still live — covered by normal results
    if (!credentialName.toLowerCase().includes(q)) continue;
    ghosts.push({
      name: credentialName,
      live: false,
      note: 'No longer live — this name had a recent change and may have been deleted or merged away.',
      changeId: latest.changeId,
      action: latest.action,
      timestamp: latest.timestamp,
      actor: latest.actor,
    });
  }
  return ghosts;
}

// ─── Tool dispatch ─────────────────────────────────────────────────────

async function callTool(name, args) {
  args = args || {};
  switch (name) {
    case 'credmgr_get': {
      const v = await credmgr.get(args.name, { source: AGENT_TAG });
      if (typeof v === 'string') return { content: [{ type: 'text', text: v }] };
      const rc = redactedChangeFor(args.name);
      const hint = rc
        ? ' It was ' + rc.action + ' on ' + rc.timestamp + ' (actor: ' + rc.actor + ', changeId: ' + rc.changeId +
          '). If that was a mistake, call credmgr_undo with this changeId.'
        : '';
      return errorResult('Not found: ' + args.name + '.' + hint);
    }
    case 'credmgr_search': {
      const latestMap = loadLatestChangeMap();
      const items = credmgr.search(args.query || '').map((i) => withRecentChange(i, latestMap));
      const liveNames = new Set(items.map(i => i.name));
      const ghosts = ghostMatches(args.query, liveNames, latestMap);
      return jsonResult(ghosts.length ? items.concat(ghosts) : items);
    }
    case 'credmgr_list': {
      const latestMap = loadLatestChangeMap();
      const items = credmgr.list({
        project: args.project, category: args.category,
        tag: args.tag, sensitivity: args.sensitivity,
      }).map((i) => withRecentChange(i, latestMap));
      return jsonResult(items);
    }
    case 'credmgr_list_projects': {
      return jsonResult(credmgr.listProjects());
    }
    case 'credmgr_get_metadata': {
      const m = credmgr.getMetadata(args.name);
      if (!m) {
        const rc = redactedChangeFor(args.name);
        if (rc) {
          return jsonResult({
            name: args.name, live: false,
            note: 'No longer live — see recentChange. If that was a mistake, call credmgr_undo with this changeId.',
            recentChange: rc,
          });
        }
        return errorResult('Not found: ' + args.name);
      }
      return jsonResult(withRecentChange(m));
    }
    case 'credmgr_recent_changes': {
      return jsonResult(credmgr.recentChanges(args.name));
    }
    case 'credmgr_set': {
      if (!ALLOW_WRITES) return errorResult('Write tools disabled (launched with --read-only).');
      const meta = credmgr.set(args.name, args.value, {
        project: args.project, category: args.category,
        sensitivity: args.sensitivity, description: args.description, tags: args.tags,
      });
      return jsonResult({ ok: true, ref: meta.ref, name: meta.name });
    }
    case 'credmgr_rotate': {
      if (!ALLOW_WRITES) return errorResult('Write tools disabled (launched with --read-only).');
      const r = credmgr.rotate(args.name, args.value);
      return jsonResult({ ok: true, ref: r.ref, name: r.name });
    }
    case 'credmgr_remove': {
      if (!ALLOW_WRITES) return errorResult('Write tools disabled (launched with --read-only).');
      const removed = credmgr.remove(args.name);
      if (!removed) return errorResult('Not found: ' + args.name);
      return jsonResult({ ok: true, removed: args.name, recoverable: 'credmgr_undo for 7 days' });
    }
    case 'credmgr_undo': {
      if (!ALLOW_WRITES) return errorResult('Write tools disabled (launched with --read-only).');
      const r = credmgr.undo(args.changeId, args.mode);
      return r.success ? jsonResult(r) : errorResult(r.message);
    }
    default:
      return errorResult('Unknown tool: ' + name);
  }
}

function jsonResult(data) {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
}
function errorResult(message) {
  return { content: [{ type: 'text', text: message }], isError: true };
}

// ─── JSON-RPC over stdio ───────────────────────────────────────────────

function send(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

function ok(id, result) { send({ jsonrpc: '2.0', id, result }); }
function fail(id, code, message) { send({ jsonrpc: '2.0', id, error: { code, message } }); }

async function handleRequest(msg) {
  const { id, method, params } = msg;

  try {
    switch (method) {
      case 'initialize':
        return ok(id, {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        });

      case 'notifications/initialized':
        return; // no response

      case 'tools/list':
        return ok(id, { tools: currentTools() });

      case 'tools/call': {
        const result = await callTool(params && params.name, params && params.arguments);
        return ok(id, result);
      }

      case 'ping':
        return ok(id, {});

      default:
        return fail(id, -32601, 'Method not found: ' + method);
    }
  } catch (err) {
    return fail(id, -32000, err && err.message ? err.message : String(err));
  }
}

function run() {
  let buf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch {
        // invalid JSON line — skip
        continue;
      }
      if (Array.isArray(msg)) {
        // batch request
        for (const m of msg) handleRequest(m);
      } else {
        handleRequest(msg);
      }
    }
  });
  process.stdin.on('end', () => process.exit(0));
  process.on('SIGINT', () => process.exit(0));
  process.on('SIGTERM', () => process.exit(0));
}

module.exports = { run };

if (require.main === module) run();
