'use strict';

const express = require('express');
const path = require('path');
const nodeCrypto = require('crypto');
const store = require('./store');
const changelog = require('./changelog');
const cryptoLib = require('./crypto');
const lock = require('./lock');

const DASHBOARD_DIR = path.join(__dirname, '..', 'dashboard');

// Constant-time bearer-token comparison so brute-force probes can't leak the
// token via response timing.
function safeEqualTokens(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  try {
    return nodeCrypto.timingSafeEqual(ab, bb);
  } catch {
    return false;
  }
}

function extractBearer(headerValue) {
  if (!headerValue || typeof headerValue !== 'string') return '';
  const trimmed = headerValue.trim();
  if (!trimmed.toLowerCase().startsWith('bearer ')) return '';
  return trimmed.slice(7).trim();
}

// Express routes are case-insensitive and accept a trailing slash by default.
// Security comparisons must recognize exactly those same route spellings;
// canonicalize only this comparison string, preserving credential-name case.
function apiPath(req) {
  return req.path.toLowerCase().replace(/\/+$/, '');
}

// Accepts:
//   falsy          → returns null (CORS disabled)
//   true           → localhost-only allowlist (for dev convenience)
//   string         → single origin allowed
//   string[]       → explicit list of allowed origins
// Returns a Set<string> of exact origins, or null.
// We never reflect the request Origin back when we don't recognise it — that
// combined with Allow-Credentials: true would let any site read credentials.
function normalizeAllowedOrigins(input) {
  if (!input) return null;
  if (input === true) {
    return new Set([
      'http://127.0.0.1:9876',
      'http://localhost:9876',
    ]);
  }
  const arr = Array.isArray(input) ? input : [input];
  const set = new Set();
  for (const item of arr) {
    if (typeof item === 'string' && item.trim()) set.add(item.trim());
  }
  return set.size > 0 ? set : null;
}

function createApp(opts) {
  const app = express();

  const token = (opts && opts.token) || null;
  const savedToken = opts && opts.tokenSource === 'saved';
  const tokenRequired = !!token || !!savedToken;

  // CORS — strict allowlist, no origin-reflection. An operator who wants a
  // browser extension or LAN tool to reach the daemon must enumerate its
  // exact origin(s) — we never echo the request Origin back. Combined with
  // Access-Control-Allow-Credentials this would otherwise let any site read
  // the caller's credentials.
  const corsOrigins = normalizeAllowedOrigins(opts && opts.allowCors);

  // Security headers on every response. The dashboard loads a single external
  // script (app.js) and no inline <script>, so script-src 'self' is real XSS
  // protection. style-src needs 'unsafe-inline' because the UI sets element
  // .style dynamically and uses style= attributes; that's a far smaller risk
  // than inline script. Fonts are system stacks only — zero network egress.
  app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "font-src 'self'",
      "img-src 'self' data:",
      "connect-src 'self'",
      "manifest-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join('; '));
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (apiPath(req).startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
    next();
  });

  // Binding to loopback alone does not stop DNS rebinding: a hostile site can
  // resolve its own hostname to 127.0.0.1 and make same-origin API reads. Keep
  // default local servers on explicit loopback Host names. A deliberate LAN
  // bind uses the daemon's bearer gate and is a different trust boundary.
  const loopbackBind = !opts || !opts.bind || ['127.0.0.1', 'localhost', '::1'].includes(opts.bind);
  app.use((req, res, next) => {
    if (loopbackBind && apiPath(req).startsWith('/api/') &&
        !['127.0.0.1', 'localhost', '::1', '[::1]'].includes((req.hostname || '').toLowerCase())) {
      return res.status(403).json({ error: 'Loopback API requires a loopback Host' });
    }
    next();
  });

  app.use(express.json());

  if (corsOrigins) {
    app.use((req, res, next) => {
      const requestOrigin = req.headers.origin;
      // Strict allowlist: echo the origin ONLY if it exactly matches an
      // entry in corsOrigins (byte-equal, set membership). Any other origin
      // (including 'null' and unknown sites) gets no CORS headers and a 403
      // preflight. This is the safe pattern — verified in tests/server.test.js.
      // Semgrep's generic cors-misconfiguration rule can't see the allowlist
      // guard; the nosemgrep below is backed by that test.
      if (requestOrigin && corsOrigins.has(requestOrigin)) {
        // nosemgrep: javascript.express.security.cors-misconfiguration.cors-misconfiguration
        res.setHeader('Access-Control-Allow-Origin', requestOrigin);
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Authorization,Content-Type,X-Credmgr-Source,X-Credmgr-Session');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      }
      if (req.method === 'OPTIONS') {
        return res.status(requestOrigin && corsOrigins.has(requestOrigin) ? 204 : 403).end();
      }
      next();
    });
  }

  // Optional bearer-token auth for every /api/* request. Health check stays
  // public so clients can probe whether the daemon is up. Failed attempts are
  // rate-limited (5 → 30 s, doubling) so the token can't be brute-forced.
  if (tokenRequired) {
    app.use((req, res, next) => {
      if (!apiPath(req).startsWith('/api/')) return next();
      if (apiPath(req) === '/api/health') return next();

      const rlKey = 'bearer:' + (req.ip || 'local');
      const blocked = lock.blockedMs(rlKey);
      if (blocked > 0) {
        res.setHeader('Retry-After', Math.ceil(blocked / 1000));
        return res.status(429).json({ error: 'Too many failed auth attempts — retry in ' + Math.ceil(blocked / 1000) + 's' });
      }

      const presented = extractBearer(req.headers['authorization']);
      // Saved tokens are revocable without restarting the daemon. Absence or
      // unreadability keeps this gate closed; explicit/env tokens stay fixed.
      const expected = savedToken ? store.getDaemonToken(opts) : token;
      if (!safeEqualTokens(presented, expected)) {
        const f = lock.recordFailure(rlKey);
        console.log('[credmgr] ' + new Date().toISOString() + ' AUTH-FAIL bearer ' +
          req.method + ' ' + req.path + ' (failure #' + f.count + ')');
        return res.status(401).json({ error: 'Unauthorized — missing or invalid bearer token' });
      }
      lock.recordSuccess(rlKey);
      // Mark the request as agent-authenticated: bearer callers bypass the
      // PIN gate below unless requirePinForAgents is set.
      req.credmgrAgent = true;
      next();
    });
  }

  // ─── PIN vault lock (opt-in) ───────────────────────────────────────────────
  // When a PIN is registered, the value-revealing surface requires an unlock
  // session (X-Credmgr-Session header from POST /api/unlock). Metadata stays
  // free so the credential list renders while locked. With no PIN registered,
  // every request behaves exactly as before — the feature is fully opt-in.
  //
  // Bearer-authenticated agent calls bypass the PIN by design (the token is
  // the agent gate; the PIN is the interactive-dashboard gate) unless the
  // operator sets requirePinForAgents in .credmgr/config.json.

  function isValueRevealing(req) {
    const p = apiPath(req);
    if (req.method === 'GET' || req.method === 'HEAD') {
      if (/^\/api\/credentials\/[^/]+\/value$/.test(p)) return true;
      if (p.startsWith('/api/ref/')) return true;
      if (p.startsWith('/api/export/')) return true;
      // Single changelog entry with ?reveal=1 returns raw previous/new values
      if (p.startsWith('/api/changelog/') && req.query && req.query.reveal === '1') return true;
      if (p === '/api/daemon-token') return true;
    }
    if (req.method === 'POST') {
      if (p.startsWith('/api/daemon-token/')) return true;      // rotate reveals the new token
      if (p.startsWith('/api/merge')) return true;              // merge reads source values
      if (p === '/api/backup' && req.body && req.body.includeKey) return true;
    }
    return false;
  }

  app.use((req, res, next) => {
    if (!apiPath(req).startsWith('/api/')) return next();
    if (!lock.hasPin(opts)) return next();
    if (req.credmgrAgent && !lock.getSettings(opts).requirePinForAgents) return next();
    if (!isValueRevealing(req)) return next();

    const sid = req.headers['x-credmgr-session'];
    if (lock.validateSession(sid, opts)) return next();
    return res.status(401).json({ error: 'Vault is locked — unlock with your PIN', locked: true });
  });

  // ─── Export password (opt-in, independent of PIN/bearer) ─────────────────
  // Whole-vault export/backup is high-stakes enough to need its OWN proof —
  // deliberately checked with no exceptions for an already-open PIN session
  // or an agent's bearer token, and with no session/TTL (re-entered every
  // time), unlike the PIN's day-to-day convenience unlock.
  function isExportSurface(req) {
    if ((req.method === 'GET' || req.method === 'HEAD') && apiPath(req).startsWith('/api/export/')) return true;
    if (req.method === 'POST' && apiPath(req) === '/api/backup' && req.body && req.body.includeKey) return true;
    return false;
  }
  app.use((req, res, next) => {
    if (!apiPath(req).startsWith('/api/')) return next();
    if (!lock.hasExportPassword(opts)) return next();
    if (!isExportSurface(req)) return next();

    const rlKey = 'exportpw:' + (req.ip || 'local');
    const blocked = lock.blockedMs(rlKey);
    if (blocked > 0) {
      res.setHeader('Retry-After', Math.ceil(blocked / 1000));
      return res.status(429).json({ error: 'Too many failed export-password attempts — retry in ' + Math.ceil(blocked / 1000) + 's' });
    }

    const presented = req.headers['x-credmgr-export-auth'];
    if (!lock.verifyExportPassword(presented, opts)) {
      lock.recordFailure(rlKey);
      return res.status(401).json({ error: 'Export requires the export password', exportLocked: true });
    }
    lock.recordSuccess(rlKey);
    next();
  });

  // Mutation log: every state-changing API call gets one clear console line
  // (timestamp, method, path — never bodies/values). The vault's own
  // changelog records WHAT changed; this records that a request happened,
  // which is the missing piece when diagnosing "who touched the daemon".
  app.use((req, res, next) => {
    if (apiPath(req).startsWith('/api/') && req.method !== 'GET' && req.method !== 'OPTIONS') {
      res.on('finish', () => {
        console.log('[credmgr] ' + new Date().toISOString() + ' ' + req.method + ' ' +
          req.path + ' → ' + res.statusCode);
      });
    }
    next();
  });

  app.use(express.static(DASHBOARD_DIR));

  // ─── API Routes ────────────────────────────────────────────────────────────

  // Health check
  app.get('/api/health', (_req, res) => {
    const verification = cryptoLib.verify(opts);
    res.json({ ok: verification.ok, errors: verification.errors });
  });

  // ─── Vault lock endpoints ─────────────────────────────────────────────────

  // Lock status — public (the dashboard needs it to render the lock screen).
  // Reports whether THIS caller's session (if presented) is currently valid.
  app.get('/api/lock-status', (req, res) => {
    try {
      const settings = lock.getSettings(opts);
      const sid = req.headers['x-credmgr-session'];
      const unlocked = !settings.pinSet || lock.validateSession(sid, opts);
      res.json({
        pinSet: settings.pinSet,
        locked: !unlocked,
        ttlMinutes: settings.lockTimeoutMinutes,
        requirePinForAgents: settings.requirePinForAgents,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Set / change / remove the PIN. Changing or removing requires the current
  // PIN. Failed current-PIN checks are rate-limited like unlock attempts.
  app.post('/api/pin', (req, res) => {
    try {
      const { pin, currentPin, remove, lockTimeoutMinutes } = req.body || {};
      const rlKey = 'pin:' + (req.ip || 'local');
      const blocked = lock.blockedMs(rlKey);
      if (blocked > 0) {
        res.setHeader('Retry-After', Math.ceil(blocked / 1000));
        return res.status(429).json({ error: 'Too many failed PIN attempts — retry in ' + Math.ceil(blocked / 1000) + 's' });
      }
      if (lockTimeoutMinutes != null) {
        // Changing the auto-lock TTL is a security setting: once a PIN is
        // registered it needs proof — a live unlock session or the current
        // PIN. (With no PIN set there is nothing to protect yet.)
        if (lock.hasPin(opts)) {
          const sid = req.headers['x-credmgr-session'];
          const authorized = lock.validateSession(sid, opts) ||
            (currentPin != null && lock.verifyPin(String(currentPin), opts));
          if (!authorized) {
            lock.recordFailure(rlKey);
            return res.status(401).json({ error: 'Unlock (or provide currentPin) to change the auto-lock timeout', locked: true });
          }
        }
        lock.setLockTimeout(lockTimeoutMinutes, opts);
      }
      if (remove) {
        lock.removePin(String(currentPin || ''), opts);
        lock.recordSuccess(rlKey);
        return res.json({ ok: true, pinSet: false });
      }
      if (pin != null) {
        lock.setPin(String(pin), currentPin != null ? String(currentPin) : '', opts);
        lock.recordSuccess(rlKey);
        // A fresh PIN means the caller just proved knowledge of it — hand
        // back an unlock session so setting a PIN doesn't lock you out.
        return res.json({ ok: true, pinSet: true, session: lock.createSession(opts) });
      }
      res.json({ ok: true, pinSet: lock.hasPin(opts) });
    } catch (err) {
      if (/incorrect/i.test(err.message)) {
        lock.recordFailure('pin:' + (req.ip || 'local'));
        console.log('[credmgr] ' + new Date().toISOString() + ' AUTH-FAIL pin-change attempt');
        return res.status(401).json({ error: err.message });
      }
      res.status(400).json({ error: err.message });
    }
  });

  // Unlock with the PIN → returns a session id, sent back on each request as
  // X-Credmgr-Session. Sliding TTL. Rate-limited (5 failures → 30 s, doubling).
  app.post('/api/unlock', (req, res) => {
    try {
      const rlKey = 'pin:' + (req.ip || 'local');
      const blocked = lock.blockedMs(rlKey);
      if (blocked > 0) {
        res.setHeader('Retry-After', Math.ceil(blocked / 1000));
        return res.status(429).json({ error: 'Too many failed PIN attempts — retry in ' + Math.ceil(blocked / 1000) + 's' });
      }
      if (!lock.hasPin(opts)) return res.status(400).json({ error: 'No PIN is registered' });
      const pin = req.body && req.body.pin != null ? String(req.body.pin) : '';
      if (!lock.verifyPin(pin, opts)) {
        const f = lock.recordFailure(rlKey);
        console.log('[credmgr] ' + new Date().toISOString() + ' AUTH-FAIL unlock (failure #' + f.count + ')');
        return res.status(401).json({ error: 'Incorrect PIN' });
      }
      lock.recordSuccess(rlKey);
      res.json({ session: lock.createSession(opts), ttlMinutes: lock.getSettings(opts).lockTimeoutMinutes });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Lock now — revokes the presented session (or all, with { all: true }).
  app.post('/api/lock', (req, res) => {
    try {
      if (req.body && req.body.all) lock.revokeAllSessions();
      else lock.revokeSession(req.headers['x-credmgr-session']);
      res.json({ ok: true, locked: lock.hasPin(opts) });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── Export password (separate secret, gates /api/export & keyed backup) ──
  app.get('/api/export-password', (_req, res) => {
    try { res.json({ set: lock.hasExportPassword(opts) }); }
    catch (err) { res.status(500).json({ error: err.message }); }
  });
  app.post('/api/export-password', (req, res) => {
    try {
      const { password, currentPassword, remove } = req.body || {};
      if (remove) {
        lock.removeExportPassword(String(currentPassword || ''), opts);
        return res.json({ removed: true });
      }
      lock.setExportPassword(password, currentPassword, opts);
      res.json({ ok: true });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // Stats
  app.get('/api/stats', (_req, res) => {
    try {
      res.json(store.stats());
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // List all credentials (metadata only)
  app.get('/api/credentials', (req, res) => {
    try {
      const filters = {};
      if (req.query.project) filters.project = req.query.project;
      if (req.query.category) filters.category = req.query.category;
      if (req.query.tag) filters.tag = req.query.tag;
      if (req.query.sensitivity) filters.sensitivity = req.query.sensitivity;
      res.json(store.list(filters));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Search credentials
  app.get('/api/search', (req, res) => {
    try {
      const q = req.query.q || '';
      if (!q) return res.json([]);
      res.json(store.search(q));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Get credential by ref number
  app.get('/api/ref/:ref', (req, res) => {
    try {
      const ref = parseInt(req.params.ref, 10);
      if (isNaN(ref)) return res.status(400).json({ error: 'Invalid ref number' });
      const result = store.getByRef(ref, opts, 'api');
      if (!result) return res.status(404).json({ error: 'Not found' });
      res.json({ name: result.metadata.name, value: result.value, metadata: result.metadata });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Per-credential version history (from the encrypted changelog; values redacted)
  app.get('/api/credentials/:name/history', (req, res) => {
    try {
      res.json(store.history(req.params.name, opts));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Get a credential value (decrypted)
  app.get('/api/credentials/:name/value', (req, res) => {
    try {
      const source = req.query.source || 'dashboard';
      const result = store.get(req.params.name, opts, source);
      if (!result) return res.status(404).json({ error: 'Not found' });
      res.json({ name: req.params.name, value: result.value, metadata: result.metadata });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Get credential metadata only
  app.get('/api/credentials/:name', (req, res) => {
    try {
      const meta = store.getMetadata(req.params.name);
      if (!meta) return res.status(404).json({ error: 'Not found' });
      res.json(meta);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Add or update a credential
  app.post('/api/credentials', (req, res) => {
    try {
      const { name, value, project, category, tags, description, sensitivity, notes, deployedTo, expiresAt, url } = req.body;
      if (!name || !value) {
        return res.status(400).json({ error: 'name and value are required' });
      }
      const meta = store.set(name, value, {
        project, category, tags, description, sensitivity, notes, deployedTo, expiresAt, url,
      }, opts);
      res.json(meta);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Update metadata only
  app.patch('/api/credentials/:name', (req, res) => {
    try {
      const result = store.updateMetadata(req.params.name, req.body, opts);
      if (!result) return res.status(404).json({ error: 'Not found' });
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Delete a credential
  app.delete('/api/credentials/:name', (req, res) => {
    try {
      const ok = store.remove(req.params.name, opts);
      if (!ok) return res.status(404).json({ error: 'Not found' });
      res.json({ deleted: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Rotate a credential
  app.post('/api/credentials/:name/rotate', (req, res) => {
    try {
      const { value } = req.body;
      if (!value) return res.status(400).json({ error: 'value is required' });
      const result = store.rotate(req.params.name, value, opts);
      if (!result) return res.status(404).json({ error: 'Not found' });
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Export env for a project. ?aliases=1 also writes each entry's absorbed
  // old names (both spellings), for consumers not yet updated after a merge.
  app.get('/api/export/:project', (req, res) => {
    try {
      const env = store.exportEnv(req.params.project, opts, { includeAliases: req.query.aliases === '1' });
      res.type('text/plain').send(env);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // List projects
  app.get('/api/projects', (_req, res) => {
    try {
      res.json(store.listProjects());
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Bulk reassign every credential from one project to another. Useful when
  // a project was renamed/retired and its creds still reference the old id,
  // or when collapsing a project into "global".
  app.post('/api/projects/:id/reassign', (req, res) => {
    try {
      const { toProjectId } = req.body || {};
      if (!toProjectId) return res.status(400).json({ error: 'toProjectId is required' });
      const result = store.reassignProject(req.params.id, toProjectId, opts);
      res.json(result);
    } catch (err) {
      const status = err.message.includes('not found') ? 404 : 400;
      res.status(status).json({ error: err.message });
    }
  });

  // Batch add/update credentials. Accepts { credentials: [ item, … ] } where
  // each item is ONE of:
  //   { name, value }                            → flat credential
  //   { name, fields:[{label,value}] }           → one structured entry (sub-credentials)
  //   { name, address, privateKey, seedPhrase }  → one structured wallet entry
  // A batch of wallets therefore produces one structured entry per wallet —
  // never a single blob, never scattered fields. Per-item failures are
  // reported without aborting the batch. Pass dryRun:true to get the same
  // added/skipped/conflicts/errors counts without writing anything.
  app.post('/api/credentials/batch', (req, res) => {
    try {
      const items = (req.body && req.body.credentials) || [];
      if (!Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ error: 'credentials array is required' });
      }
      const result = store.batchImport(items, {
        batchGroup: req.body && typeof req.body.batchGroup === 'string' ? req.body.batchGroup.trim() : undefined,
        overwrite: !!(req.body && req.body.overwrite),
        defaultProject: req.body && req.body.defaultProject,
        dryRun: !!(req.body && req.body.dryRun),
      }, opts);
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Daemon/agent auth token — same knob as `credmgr token generate/show/revoke`,
  // surfaced here so the dashboard can show status + rotate/revoke without a
  // terminal. Gated behind the same bearer-auth as every other /api/* route.
  // GitHub-PAT model: status returns existence + last4 only, NEVER the full
  // value. The full token is shown exactly once — in the rotate response.
  // (CLI `credmgr token show` still works: local file read, different trust
  // domain than the HTTP surface.)
  app.get('/api/daemon-token', (_req, res) => {
    try {
      const token = store.getDaemonToken(opts);
      res.json({ hasToken: !!token, last4: token ? token.slice(-4) : null });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });
  app.post('/api/daemon-token/rotate', (_req, res) => {
    try { res.json({ token: store.rotateDaemonToken(opts), shownOnce: true }); }
    catch (err) { res.status(500).json({ error: err.message }); }
  });
  app.post('/api/daemon-token/revoke', (_req, res) => {
    try { store.revokeDaemonToken(opts); res.json({ ok: true }); }
    catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ── AI-agent integrations (Claude/ChatGPT/etc via `credmgr mcp`) ────────
  // This registry is the enable/disable switch for that surface — the
  // enforcement itself happens in mcp/server.js at process launch, not here.
  // See lib/integrations.js for the gate model (opt-in, then sticky).
  const integrations = require('./integrations');
  app.get('/api/integrations', (_req, res) => {
    try { res.json(integrations.status()); }
    catch (err) { res.status(500).json({ error: err.message }); }
  });
  app.post('/api/integrations', (req, res) => {
    try { res.json(integrations.create(req.body || {})); }
    catch (err) { res.status(400).json({ error: err.message }); }
  });
  app.post('/api/integrations/:id/toggle', (req, res) => {
    try { res.json(integrations.setEnabled(req.params.id, !!(req.body && req.body.enabled))); }
    catch (err) { res.status(404).json({ error: err.message }); }
  });
  app.delete('/api/integrations/:id', (req, res) => {
    try { res.json(integrations.remove(req.params.id)); }
    catch (err) { res.status(500).json({ error: err.message }); }
  });

  // Rename a project's display name (id/slug stays the same)
  app.patch('/api/projects/:id', (req, res) => {
    try {
      const { name } = req.body;
      if (!name) return res.status(400).json({ error: 'name is required' });
      const result = store.renameProject(req.params.id, name);
      res.json(result);
    } catch (err) {
      const status = err.message.includes('not found') ? 404 : 500;
      res.status(status).json({ error: err.message });
    }
  });

  // Remove a project so it stops appearing as a taggable option. Refuses
  // (400) while any credential still references it — reassign or remove
  // those first (see store.removeProject).
  app.delete('/api/projects/:id', (req, res) => {
    try {
      const result = store.removeProject(req.params.id);
      res.json(result);
    } catch (err) {
      const status = err.message.includes('not found') ? 404 : 400;
      res.status(status).json({ error: err.message });
    }
  });

  // Smart merge/duplicate suggestions. Dismissed groups are hidden by
  // default — ?includeDismissed=1 is for the Settings "manage dismissed" view.
  app.get('/api/suggestions', (req, res) => {
    try {
      res.json(store.findMergeSuggestions(opts, { includeDismissed: req.query.includeDismissed === '1' }));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Persist a suggestion rejection so it stops reappearing on every scan.
  // `key` must be the exact key the suggestion was returned with above.
  app.post('/api/suggestions/dismiss', (req, res) => {
    try {
      res.json(store.dismissSuggestion(req.body && req.body.key));
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post('/api/suggestions/undismiss', (req, res) => {
    try {
      res.json(store.undismissSuggestion(req.body && req.body.key));
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  app.get('/api/suggestions/dismissed', (_req, res) => {
    try {
      res.json(store.listDismissedSuggestions());
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/suggestions/restore-all', (_req, res) => {
    try {
      res.json(store.restoreAllDismissedSuggestions());
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Changelog. Values are ALWAYS redacted here — the raw records hold
  // plaintext previous/new secrets (that's what makes undo work), but the
  // wire format must never carry them by default. Full record only via
  // GET /api/changelog/:changeId?reveal=1 (PIN-gated when a PIN is set).
  const redactChange = (c) => Object.assign({}, c, {
    previousValue: c.previousValue ? '[redacted]' : null,
    newValue: c.newValue ? '[redacted]' : null,
  });

  app.get('/api/changelog', (_req, res) => {
    try {
      res.json(changelog.listChanges(opts).map(redactChange));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Single changelog entry. Redacted unless ?reveal=1 (a value-revealing
  // surface — included in the PIN gate list above).
  app.get('/api/changelog/:changeId', (req, res) => {
    try {
      const change = changelog.getChange(req.params.changeId, opts);
      if (!change) return res.status(404).json({ error: 'Not found' });
      res.json(req.query.reveal === '1' ? change : redactChange(change));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Undo a change. Accepts optional { mode: 'replace' | 'keep-both' } body.
  // 'keep-both' restores the previous value as a new credential named
  // "<name> old" while leaving the current credential untouched.
  app.post('/api/changelog/:changeId/undo', (req, res) => {
    try {
      const mode = (req.body && req.body.mode) === 'keep-both' ? 'keep-both' : 'replace';
      const result = changelog.undo(req.params.changeId, opts, { mode });
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Empty the recovery archive early — permanently delete changelog entries
  // NOW instead of waiting out the 7-day retention. Body (optional):
  // { olderThanDays: n } to only purge entries older than n days.
  app.post('/api/changelog/purge', (req, res) => {
    try {
      const olderThanDays = req.body && req.body.olderThanDays != null
        ? parseInt(req.body.olderThanDays, 10)
        : null;
      const result = changelog.purgeAll(olderThanDays != null && !isNaN(olderThanDays) ? { olderThanDays } : {});
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Permanently delete a changelog entry (per-item history delete).
  // After deletion, the change can no longer be undone.
  app.delete('/api/changelog/:changeId', (req, res) => {
    try {
      const result = changelog.deleteEntry(req.params.changeId);
      if (!result.success) return res.status(404).json(result);
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Type schemas — the canonical "columns" per item type (wallet, server,
  // database, …). The dashboard uses these for Add-form presets, the edit
  // panel's add-column chips, and missing-column hints.
  app.get('/api/schemas', (_req, res) => {
    res.json(store.TYPE_SCHEMAS);
  });

  // Batch auto-merge: merge EVERY safe suggestion group in one call.
  // Body: { dryRun: true } returns the plan without writing anything.
  app.post('/api/merge/auto-all', (req, res) => {
    try {
      res.json(store.autoMergeAll({ dryRun: !!(req.body && req.body.dryRun) }, opts));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Auto-merge: combine matched credentials into ONE structured entry with
  // canonical field labels derived from their name suffixes (USER → username,
  // PASS → password, "private key" → privateKey, …), then archive the
  // sources (recoverable for 7 days). Body: { sourceNames, newName?,
  // project?, category?, description?, ref? }.
  app.post('/api/merge/auto', (req, res) => {
    try {
      const { sourceNames, newName, project, category, description, ref } = req.body || {};
      if (!Array.isArray(sourceNames) || sourceNames.length < 2) {
        return res.status(400).json({ error: 'sourceNames must list at least 2 credentials' });
      }
      const result = store.autoMerge(sourceNames, { newName, project, category, description, ref }, opts);
      res.json(result);
    } catch (err) {
      const status = err.message.includes('not found') ? 404 : 400;
      res.status(status).json({ error: err.message });
    }
  });

  // Merge credentials
  app.post('/api/merge', (req, res) => {
    try {
      const { sourceNames, newName, fields, project, category, sensitivity, description, tags, ref } = req.body;
      if (!sourceNames || !newName || !fields) {
        return res.status(400).json({ error: 'sourceNames, newName, and fields are required' });
      }
      const meta = {};
      if (project) meta.project = project;
      if (category) meta.category = category;
      if (sensitivity) meta.sensitivity = sensitivity;
      if (description) meta.description = description;
      if (tags) meta.tags = tags;
      if (ref) meta.ref = ref;
      const result = store.merge(sourceNames, newName, fields, meta, opts);
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Verify integrity
  app.get('/api/verify', (_req, res) => {
    try {
      res.json(store.verifyIntegrity(opts));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Doctor — diagnose (and optionally repair) store inconsistencies.
  // Body: { fix: boolean } — false/absent = dry run.
  app.post('/api/doctor', (req, res) => {
    try {
      const apply = !!(req.body && req.body.fix);
      const integrity = store.verifyIntegrity(opts);
      const heal = store.healStore(opts, { apply });
      res.json({ integrity, heal });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Encrypted backup snapshot. Body: { includeKey: boolean }.
  // Returns the path — the file itself stays on the local machine.
  app.post('/api/backup', (req, res) => {
    try {
      const includeKey = !!(req.body && req.body.includeKey);
      const retain = req.body && req.body.retain != null ? req.body.retain : undefined;
      res.json(store.backup({ includeKey, retain }, opts));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── Machine-lock (bind the vault's identity to this machine) ────────────
  // Same verify-then-rollback safety as the CLI (bin/credmgr machine-lock):
  // enabling runs a real encrypt/decrypt round-trip immediately afterward
  // and automatically undoes the lock if that fails, so this can never leave
  // the vault stuck. See lib/machine-lock.js for the actual mechanism.
  const machineLock = require('./machine-lock');
  app.get('/api/machine-lock', (_req, res) => {
    try { res.json(machineLock.status(opts)); }
    catch (err) { res.status(500).json({ error: err.message }); }
  });
  app.post('/api/machine-lock/enable', (_req, res) => {
    try {
      if (machineLock.isEnabled(opts)) return res.status(400).json({ error: 'Machine lock is already enabled' });
      const identityPath = cryptoLib.getIdentityPath(opts);
      machineLock.enable(identityPath, opts);
      try {
        const probe = 'credmgr-machine-lock-verify-' + Date.now();
        const enc = cryptoLib.encrypt(probe, opts);
        const dec = cryptoLib.decrypt(enc, opts);
        if (dec.trim() !== probe) throw new Error('round-trip value mismatch');
      } catch (verifyErr) {
        try { machineLock.disable(identityPath, opts); } catch (_) { /* best-effort */ }
        return res.status(500).json({ error: 'Verification failed after enabling — rolled back automatically: ' + verifyErr.message });
      }
      res.json(machineLock.status(opts));
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });
  app.post('/api/machine-lock/disable', (_req, res) => {
    try {
      const identityPath = cryptoLib.getIdentityPath(opts);
      machineLock.disable(identityPath, opts);
      res.json(machineLock.status(opts));
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // Generate a cryptographically-random secret (for the Add form's Generate
  // button). Query: length, type (password|alnum|hex|base64url), symbols=0.
  app.get('/api/generate', (req, res) => {
    try {
      const length = parseInt(req.query.length || '32', 10);
      const type = req.query.type || 'password';
      const symbols = req.query.symbols !== '0';
      res.json({ value: store.generateSecret({ length, type, symbols }) });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Expiring credentials
  app.get('/api/expiring', (req, res) => {
    try {
      const days = parseInt(req.query.days || '7', 10);
      res.json(store.expiring(days));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Health audit
  app.get('/api/audit', (_req, res) => {
    try {
      res.json(store.audit(opts));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Daemon self-description — the dashboard's trust pill and footer are
  // driven from this instead of guessing from window.location. bind and
  // tokenRequired come straight from the options this process started with.
  const startedAt = Date.now();
  app.get('/api/status', (_req, res) => {
    let version = null;
    try { version = require('../package.json').version; } catch { /* optional */ }
    res.json({
      bind: (opts && opts.bind) || '127.0.0.1',
      tokenRequired,
      pinSet: lock.hasPin(opts),
      version,
      uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
    });
  });

  // Access log
  app.get('/api/access-log', (req, res) => {
    try {
      const filters = {};
      if (req.query.name) filters.name = req.query.name;
      if (req.query.source) filters.source = req.query.source;
      if (req.query.limit) filters.limit = parseInt(req.query.limit, 10);
      res.json(store.getAccessLog(filters));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // SPA fallback
  app.get('*', (_req, res) => {
    res.sendFile(path.join(DASHBOARD_DIR, 'index.html'));
  });

  return app;
}

function start(port, opts) {
  const app = createApp(opts);
  const bind = (opts && opts.bind) || '127.0.0.1';
  const server = app.listen(port, bind, () => {
    const addr = server.address();
    const host = bind === '0.0.0.0' ? '0.0.0.0' : '127.0.0.1';
    const label = (opts && opts.headless) ? 'daemon' : 'dashboard';
    console.log('credmgr ' + label + ' running at http://' + host + ':' + addr.port);
    if (opts && opts.token) {
      console.log('  auth:  bearer-token required (set CREDMGR_TOKEN on clients)');
    } else if (bind !== '127.0.0.1') {
      console.log('  WARNING: bound to ' + bind + ' without a token — anyone on your network can read secrets.');
    }
  });
  return server;
}

module.exports = { createApp, start };
