'use strict';

// Server-side vault lock: PIN (scrypt) + in-memory unlock sessions.
//
// Threat-model split (deliberate two-audience design, documented in CLAUDE.md):
//   - The PIN gates the *interactive dashboard* surface — value reveals,
//     exports, merges — served on localhost without a bearer token.
//   - Headless agents authenticate with the daemon bearer token and bypass
//     PIN sessions, unless `requirePinForAgents: true` is set in config.
//   - Neither protects against local shell + master.key. That is the CLI
//     trust domain; a local vault cannot defend against its own user account.
//
// Sessions live ONLY in this process's memory (Map id → expiry). A restart
// locks everything — that is a feature, not a bug.

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const cryptoLib = require('./crypto');

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };
const DEFAULT_TTL_MINUTES = 15;

// ─── Config (shares .credmgr/config.json with the crypto key paths) ─────────

function configPath(opts) {
  return (opts && opts.configPath) || path.join(cryptoLib.CREDMGR_DIR, 'config.json');
}

function readConfig(opts) {
  const p = configPath(opts);
  let raw;
  try { raw = fs.readFileSync(p, 'utf8'); }
  catch (err) {
    if (err.code === 'ENOENT') return null;
    throw new Error('Cannot read security configuration; restore a valid config before continuing');
  }
  try {
    const cfg = JSON.parse(raw);
    if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) throw new Error();
    if (cfg.requirePinForAgents !== undefined && typeof cfg.requirePinForAgents !== 'boolean') throw new Error();
    for (const field of ['pin', 'exportPassword']) {
      if (cfg[field] !== undefined && (!cfg[field] ||
          !/^[a-f0-9]{64}$/i.test(cfg[field].hash) || !/^[a-f0-9]{32}$/i.test(cfg[field].salt))) throw new Error();
    }
    return cfg;
  } catch {
    throw new Error('Invalid security configuration; restore a valid config before continuing');
  }
}

// Merge-preserving write. crypto.loadConfig() falls back to the default key
// paths ONLY when config.json is ABSENT — so if we are the ones creating the
// file, we must seed keyPath/pubKeyPath or decryption breaks on next read.
function updateConfig(patch, opts) {
  let cfg = readConfig(opts);
  if (cfg === null) {
    cfg = {
      keyPath: path.join(cryptoLib.CREDMGR_DIR, 'master.key'),
      pubKeyPath: path.join(cryptoLib.CREDMGR_DIR, 'master.pub'),
    };
  }
  for (const k of Object.keys(patch)) {
    if (patch[k] === null) delete cfg[k];
    else cfg[k] = patch[k];
  }
  const p = configPath(opts);
  const dir = path.dirname(p);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(p, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
  try { fs.chmodSync(p, 0o600); } catch { /* already 0600 on create */ }
  return cfg;
}

// ─── PIN (scrypt hash at rest, constant-time compare) ───────────────────────

function derive(pin, saltHex, params) {
  const p = params || SCRYPT;
  return nodeCrypto.scryptSync(String(pin), Buffer.from(saltHex, 'hex'), p.keylen, {
    N: p.N, r: p.r, p: p.p,
  });
}

function hasPin(opts) {
  const cfg = readConfig(opts);
  return !!(cfg && cfg.pin && cfg.pin.hash && cfg.pin.salt);
}

function verifyPin(pin, opts) {
  const cfg = readConfig(opts);
  if (!cfg || !cfg.pin || !cfg.pin.hash || !cfg.pin.salt) return false;
  if (typeof pin !== 'string' || pin.length === 0) return false;
  try {
    const expected = Buffer.from(cfg.pin.hash, 'hex');
    const actual = derive(pin, cfg.pin.salt, cfg.pin);
    return expected.length === actual.length && nodeCrypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

// Set or change the PIN. Changing (or setting while one exists) requires the
// current PIN — an unauthenticated caller must not be able to swap the lock.
function setPin(newPin, currentPin, opts) {
  if (typeof newPin !== 'string' || newPin.length < 4 || newPin.length > 64) {
    throw new Error('PIN must be 4–64 characters');
  }
  if (hasPin(opts) && !verifyPin(currentPin, opts)) {
    throw new Error('Current PIN is incorrect');
  }
  const salt = nodeCrypto.randomBytes(16).toString('hex');
  const hash = derive(newPin, salt).toString('hex');
  updateConfig({
    pin: { algo: 'scrypt', N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, keylen: SCRYPT.keylen, salt, hash },
  }, opts);
  revokeAllSessions();
}

function removePin(currentPin, opts) {
  if (!hasPin(opts)) return;
  if (!verifyPin(currentPin, opts)) throw new Error('Current PIN is incorrect');
  updateConfig({ pin: null }, opts);
  revokeAllSessions();
}

// ─── Export password (separate secret from the vault PIN, opt-in) ──────────
// Gates the whole-database export/backup surface specifically. Deliberately
// independent of the PIN and the bearer token: an already-unlocked dashboard
// session or an agent's daemon token must NOT be enough on their own to walk
// out with the entire vault — this is a second, distinct proof, checked
// per-request (no session/TTL) since export is an infrequent, high-stakes
// action, not a routine one worth trading security for convenience on.
// Same trust-domain caveat as the PIN: this gates the HTTP surface only, not
// the local CLI (`credmgr export`) — a local vault can't defend against its
// own user account either way.

function hasExportPassword(opts) {
  const cfg = readConfig(opts);
  return !!(cfg && cfg.exportPassword && cfg.exportPassword.hash && cfg.exportPassword.salt);
}

function verifyExportPassword(password, opts) {
  const cfg = readConfig(opts);
  if (!cfg || !cfg.exportPassword || !cfg.exportPassword.hash || !cfg.exportPassword.salt) return false;
  if (typeof password !== 'string' || password.length === 0) return false;
  try {
    const expected = Buffer.from(cfg.exportPassword.hash, 'hex');
    const actual = derive(password, cfg.exportPassword.salt, cfg.exportPassword);
    return expected.length === actual.length && nodeCrypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

// Longer minimum than the PIN (8, not 4) — this guards the whole vault in one
// shot, not a quick per-value unlock convenience.
function setExportPassword(newPassword, currentPassword, opts) {
  if (typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > 128) {
    throw new Error('Export password must be 8–128 characters');
  }
  if (hasExportPassword(opts) && !verifyExportPassword(currentPassword, opts)) {
    throw new Error('Current export password is incorrect');
  }
  const salt = nodeCrypto.randomBytes(16).toString('hex');
  const hash = derive(newPassword, salt).toString('hex');
  updateConfig({
    exportPassword: { algo: 'scrypt', N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, keylen: SCRYPT.keylen, salt, hash },
  }, opts);
}

function removeExportPassword(currentPassword, opts) {
  if (!hasExportPassword(opts)) return;
  if (!verifyExportPassword(currentPassword, opts)) throw new Error('Current export password is incorrect');
  updateConfig({ exportPassword: null }, opts);
}

// ─── Settings ────────────────────────────────────────────────────────────────

function getSettings(opts) {
  const cfg = readConfig(opts) || {};
  const mins = Number(cfg.lockTimeoutMinutes);
  return {
    pinSet: hasPin(opts),
    lockTimeoutMinutes: Number.isFinite(mins) && mins > 0 ? mins : DEFAULT_TTL_MINUTES,
    requirePinForAgents: cfg.requirePinForAgents === true,
  };
}

function setLockTimeout(minutes, opts) {
  const mins = Number(minutes);
  if (!Number.isFinite(mins) || mins < 1 || mins > 24 * 60) {
    throw new Error('lockTimeoutMinutes must be between 1 and 1440');
  }
  updateConfig({ lockTimeoutMinutes: mins }, opts);
}

// ─── Unlock sessions (in-memory only, sliding TTL) ───────────────────────────

const sessions = new Map(); // id → expiry epoch-ms

function ttlMs(opts) {
  return getSettings(opts).lockTimeoutMinutes * 60 * 1000;
}

function createSession(opts) {
  const id = nodeCrypto.randomBytes(32).toString('hex');
  sessions.set(id, Date.now() + ttlMs(opts));
  return id;
}

function validateSession(id, opts) {
  if (!id || typeof id !== 'string') return false;
  const expiry = sessions.get(id);
  if (!expiry) return false;
  if (Date.now() > expiry) {
    sessions.delete(id);
    return false;
  }
  sessions.set(id, Date.now() + ttlMs(opts)); // sliding renewal on activity
  return true;
}

function revokeSession(id) {
  if (id) sessions.delete(id);
}

function revokeAllSessions() {
  sessions.clear();
}

// ─── Auth rate-limiting (bearer + PIN attempts share this) ──────────────────
// 5 consecutive failures → 30 s delay, doubling per further failure (capped
// at 1 h). In-memory: a daemon restart clears the state, which is acceptable
// for a local vault — the attacker with restart rights already has the disk.

const FAILURE_THRESHOLD = 5;
const BASE_DELAY_MS = 30 * 1000;
const MAX_DELAY_MS = 60 * 60 * 1000;

const failures = new Map(); // key → { count, blockedUntil }

// Returns remaining block in ms (0 = not blocked).
function blockedMs(key) {
  const f = failures.get(key);
  if (!f || !f.blockedUntil) return 0;
  const remaining = f.blockedUntil - Date.now();
  return remaining > 0 ? remaining : 0;
}

function recordFailure(key) {
  const f = failures.get(key) || { count: 0, blockedUntil: 0 };
  f.count += 1;
  if (f.count >= FAILURE_THRESHOLD) {
    const delay = Math.min(BASE_DELAY_MS * Math.pow(2, f.count - FAILURE_THRESHOLD), MAX_DELAY_MS);
    f.blockedUntil = Date.now() + delay;
  }
  failures.set(key, f);
  return f;
}

function recordSuccess(key) {
  failures.delete(key);
}

// Test hook — never used by production code.
function _resetRateLimiter() {
  failures.clear();
}

module.exports = {
  hasPin,
  verifyPin,
  setPin,
  removePin,
  hasExportPassword,
  verifyExportPassword,
  setExportPassword,
  removeExportPassword,
  getSettings,
  setLockTimeout,
  updateConfig,
  createSession,
  validateSession,
  revokeSession,
  revokeAllSessions,
  blockedMs,
  recordFailure,
  recordSuccess,
  _resetRateLimiter,
  DEFAULT_TTL_MINUTES,
};
