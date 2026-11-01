'use strict';

const fs = require('fs');
const path = require('path');
const cryptoLib = require('./crypto');

const CHANGELOG_DIR = path.join(cryptoLib.CREDMGR_DIR, 'changelog');
const DEFAULT_RETENTION_DAYS = 7;

// ─── Black-box guarantees ────────────────────────────────────────────────
// The changelog is the vault's 7-day recovery archive. It must behave as a
// sealed box: every entry is age-encrypted with the master key (0600), the
// directory is owner-only (0700, re-asserted on every touch), entry lookups
// only ever resolve against the directory's own listing (no caller-supplied
// paths reach the filesystem), and retention decisions are made from the
// timestamp embedded in the entry's own filename — never from filesystem
// metadata an outside process could alter.

// Valid changeIds are exactly what log() generates: ISO-ish timestamp + hex.
const CHANGE_ID_RE = /^[0-9TZ-]{10,40}[a-f0-9-]*$/i;

function sanitizeChangeId(changeId) {
  const id = String(changeId || '').trim();
  if (!id || !CHANGE_ID_RE.test(id) || id.includes('..') || id.includes('/')) return null;
  return id;
}

function ensureDir() {
  if (!fs.existsSync(CHANGELOG_DIR)) {
    fs.mkdirSync(CHANGELOG_DIR, { recursive: true, mode: 0o700 });
  }
  // Re-assert owner-only permissions in case anything loosened them.
  try { fs.chmodSync(CHANGELOG_DIR, 0o700); } catch (_) { /* best-effort */ }
}

/**
 * Parse the creation time embedded in an entry filename
 * (YYYY-MM-DDTHH-MM-SS-mmmZ-hex.json.age). Returns a Date or null.
 * Using the embedded timestamp (not mtime) keeps retention decisions
 * inside the black box — touching the file from outside changes nothing.
 */
function entryTimestamp(filename) {
  const m = filename.match(/^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z/);
  if (!m) return null;
  const d = new Date(m[1] + 'T' + m[2] + ':' + m[3] + ':' + m[4] + '.' + m[5] + 'Z');
  return isNaN(d.getTime()) ? null : d;
}

/**
 * Log a change. The entry is encrypted and written as an individual file.
 */
function log(entry, opts) {
  ensureDir();

  const now = new Date();
  const changeId = now.toISOString().replace(/[:.]/g, '-') + '-' + cryptoLib.randomId(4);

  const record = {
    changeId,
    timestamp: now.toISOString(),
    action: entry.action,           // 'add', 'modify', 'delete', 'rotate', 'metadata-update'
    credentialId: entry.credentialId,
    credentialName: entry.credentialName,
    previousValue: entry.previousValue || null,
    newValue: entry.newValue || null,
    previousMetadata: entry.previousMetadata || null,
    actor: detectActor(),
  };

  const filename = changeId + '.json.age';
  const filePath = path.join(CHANGELOG_DIR, filename);

  try {
    cryptoLib.encryptToFile(JSON.stringify(record, null, 2), filePath, opts);
  } catch (err) {
    // Never block operations because of changelog failure
    process.stderr.write('[changelog] Failed to write change log: ' + err.message + '\n');
  }

  // Auto-purge expired entries
  purgeExpired(opts);

  return changeId;
}

/**
 * List recent changes (decrypted).
 * Returns array sorted newest-first.
 */
function listChanges(opts) {
  ensureDir();
  const files = fs.readdirSync(CHANGELOG_DIR)
    .filter(f => f.endsWith('.json.age'))
    .sort()
    .reverse();

  const changes = [];
  for (const file of files) {
    try {
      const filePath = path.join(CHANGELOG_DIR, file);
      const plaintext = cryptoLib.decryptFile(filePath, opts);
      changes.push(JSON.parse(plaintext));
    } catch (err) {
      // Skip corrupted entries
      process.stderr.write('[changelog] Failed to read ' + file + ': ' + err.message + '\n');
    }
  }

  return changes;
}

/**
 * Get a specific change by ID.
 */
function getChange(changeId, opts) {
  ensureDir();
  const id = sanitizeChangeId(changeId);
  if (!id) return null;
  // Resolve ONLY against the directory's own listing — never join a
  // caller-supplied string into a path. Full id or unique prefix.
  const files = fs.readdirSync(CHANGELOG_DIR)
    .filter(f => f.endsWith('.json.age') && f.startsWith(id));

  if (files.length === 0) return null;

  try {
    const filePath = path.join(CHANGELOG_DIR, files[0]);
    const plaintext = cryptoLib.decryptFile(filePath, opts);
    return JSON.parse(plaintext);
  } catch (err) {
    return null;
  }
}

/**
 * Undo a specific change. Returns { success, message }.
 *
 * This restores the previous value (for modify/delete/rotate) or
 * removes the credential (for add).
 */
function undo(changeId, opts, undoOpts) {
  const change = getChange(changeId, opts);
  if (!change) {
    return { success: false, message: 'Change not found: ' + changeId };
  }

  // Lazy-load store to avoid circular dependency
  const store = require('./store');

  // Policy: 'add' actions are permanent. Undoing an add would delete the
  // credential, which is indistinguishable from calling `rm` — and users have
  // reported confusion where an accidental undo on a fresh credential wiped
  // data they still wanted. Adds stay as adds.
  if (change.action === 'add') {
    return { success: false, message: 'Adds cannot be undone. Use `credmgr rm` to delete the credential explicitly.' };
  }

  const mode = (undoOpts && undoOpts.mode) || 'replace'; // 'replace' | 'keep-both'

  switch (change.action) {
    case 'modify':
    case 'rotate': {
      // Restore previous value
      if (change.previousValue === null) {
        return { success: false, message: 'No previous value to restore' };
      }
      const index = store.loadIndex();
      const vault = store.loadVault(opts);
      const entry = index.credentials.find(c => c.id === change.credentialId);

      if (!entry) {
        return { success: false, message: 'Credential no longer exists in index' };
      }

      // keep-both: restore the old value AS A NEW credential named "<name> old"
      // while leaving the current (new) credential untouched. Lets the user
      // compare, migrate, or reference the previous secret.
      if (mode === 'keep-both') {
        let restoredName = change.credentialName + ' old';
        let n = 2;
        while (index.credentials.find(c => c.name === restoredName)) {
          restoredName = change.credentialName + ' old ' + n;
          n++;
        }
        const restored = store.set(restoredName, change.previousValue, {
          project: entry.project,
          category: entry.category,
          tags: (entry.tags || []).concat(['restored-from-history']),
          description: (entry.description || '') + ' (restored from history on ' + new Date().toISOString().slice(0, 10) + ')',
          sensitivity: entry.sensitivity,
        }, opts);

        log({
          action: 'undo-keep-both',
          credentialId: change.credentialId,
          credentialName: change.credentialName,
          previousValue: null,
          newValue: null,
          previousMetadata: { restoredAs: restoredName },
        }, opts);

        return {
          success: true,
          message: 'Kept current ' + change.credentialName + ' and restored previous value as ' + restoredName,
          restoredName,
          restoredRef: restored && restored.ref,
        };
      }

      // replace (default): overwrite current value with previous value
      vault[change.credentialId] = change.previousValue;

      // Restore metadata if available
      if (change.previousMetadata) {
        Object.assign(entry, change.previousMetadata);
        entry.modified = new Date().toISOString();
      }

      store.saveVault(vault, opts);
      store.saveIndex(index);

      // Log the undo itself
      log({
        action: 'undo',
        credentialId: change.credentialId,
        credentialName: change.credentialName,
        previousValue: change.newValue,
        newValue: change.previousValue,
        previousMetadata: null,
      }, opts);

      return { success: true, message: 'Restored ' + change.credentialName + ' to previous value' };
    }

    case 'delete': {
      // Re-add the credential
      if (change.previousValue === null || !change.previousMetadata) {
        return { success: false, message: 'Insufficient data to restore deleted credential' };
      }

      const index = store.loadIndex();
      const vault = store.loadVault(opts);

      // Name-reuse collision: something now occupies the deleted credential's
      // old name (e.g. it was deleted by mistake, then a DIFFERENT secret was
      // later created under the same name). 'replace' mode refuses outright —
      // silently overwriting the newer credential's value would be its own
      // destructive surprise. 'keep-both' restores the deleted value under a
      // free "<name> old[, old N]" name instead, so neither secret is lost.
      const existing = index.credentials.find(c => c.name === change.credentialName);
      if (existing && mode !== 'keep-both') {
        return {
          success: false,
          message: 'Credential name "' + change.credentialName + '" already exists again ' +
            '— pass mode "keep-both" to restore the deleted one as "' + change.credentialName + ' old" ' +
            'instead of overwriting the current one.',
        };
      }

      let restoredName = change.credentialName;
      if (existing) {
        restoredName = change.credentialName + ' old';
        let n = 2;
        while (index.credentials.find(c => c.name === restoredName)) {
          restoredName = change.credentialName + ' old ' + n;
          n++;
        }
      }

      vault[change.credentialId] = change.previousValue;
      index.credentials.push({
        ...change.previousMetadata,
        name: restoredName,
        modified: new Date().toISOString(),
      });

      store.saveVault(vault, opts);
      store.saveIndex(index);

      log({
        action: 'undo-delete',
        credentialId: change.credentialId,
        credentialName: restoredName,
        previousValue: null,
        newValue: change.previousValue,
        previousMetadata: existing ? { restoredAs: restoredName, collidedWith: change.credentialName } : null,
      }, opts);

      return existing
        ? {
            success: true,
            message: 'Kept current ' + change.credentialName + ' and restored the deleted value as ' + restoredName,
            restoredName,
          }
        : { success: true, message: 'Restored deleted credential: ' + restoredName };
    }

    case 'add': {
      // Blocked above — adds are permanent. This branch is defensive only.
      return { success: false, message: 'Adds cannot be undone.' };
    }

    case 'metadata-update': {
      if (!change.previousMetadata) {
        return { success: false, message: 'No previous metadata to restore' };
      }

      const index = store.loadIndex();
      const entry = index.credentials.find(c => c.id === change.credentialId);
      if (!entry) {
        return { success: false, message: 'Credential no longer exists' };
      }

      Object.assign(entry, change.previousMetadata);
      entry.modified = new Date().toISOString();
      store.saveIndex(index);

      return { success: true, message: 'Restored metadata for ' + change.credentialName };
    }

    default:
      return { success: false, message: 'Cannot undo action type: ' + change.action };
  }
}

/**
 * Purge changelog entries older than retention period.
 */
function purgeExpired(opts) {
  ensureDir();
  const retentionDays = DEFAULT_RETENTION_DAYS;
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);

  const files = fs.readdirSync(CHANGELOG_DIR).filter(f => f.endsWith('.json.age'));

  let purged = 0;
  for (const file of files) {
    try {
      const filePath = path.join(CHANGELOG_DIR, file);
      // Retention is decided from the timestamp embedded in the filename —
      // self-contained, immune to external mtime tampering. Fall back to
      // mtime only for legacy files whose name doesn't parse.
      const ts = entryTimestamp(file) || fs.statSync(filePath).mtime;
      if (ts < cutoff) {
        fs.unlinkSync(filePath);
        purged++;
      }
    } catch (_) { /* skip */ }
  }

  return purged;
}

/**
 * Force purge all expired entries (manual command).
 */
function forcePurge() {
  return purgeExpired();
}

/**
 * Permanently delete changelog entries NOW, regardless of age — the manual
 * "empty the archive early" action. Optional filter:
 *   { olderThanDays: n }  → only entries older than n days
 * Returns { purged, remaining }.
 */
function purgeAll(o) {
  ensureDir();
  const po = o || {};
  const cutoff = po.olderThanDays != null
    ? new Date(Date.now() - po.olderThanDays * 24 * 60 * 60 * 1000)
    : null;

  const files = fs.readdirSync(CHANGELOG_DIR).filter(f => f.endsWith('.json.age'));
  let purged = 0;
  for (const file of files) {
    try {
      const filePath = path.join(CHANGELOG_DIR, file);
      if (cutoff) {
        const ts = entryTimestamp(file) || fs.statSync(filePath).mtime;
        if (ts >= cutoff) continue;
      }
      fs.unlinkSync(filePath);
      purged++;
    } catch (_) { /* skip */ }
  }
  const remaining = fs.readdirSync(CHANGELOG_DIR).filter(f => f.endsWith('.json.age')).length;
  return { purged, remaining };
}

/**
 * Permanently delete a single changelog entry. The file is unlinked from
 * disk, making that change non-reversible (undo will no longer find it).
 * Used by the dashboard's per-item history delete button.
 *
 * Returns { success, message }.
 */
function deleteEntry(changeId) {
  ensureDir();
  const id = sanitizeChangeId(changeId);
  if (!id) {
    return { success: false, message: 'Invalid change id' };
  }
  const files = fs.readdirSync(CHANGELOG_DIR).filter(f => f.endsWith('.json.age'));
  // Accept the full id or a unique prefix — resolved only against the
  // directory's own listing (black box: no caller path ever hits the fs).
  const match = files.find(f => f.startsWith(id));
  if (!match) {
    return { success: false, message: 'Change not found: ' + changeId };
  }
  try {
    const filePath = path.join(CHANGELOG_DIR, match);
    fs.unlinkSync(filePath);
    return { success: true, message: 'Permanently deleted change: ' + changeId };
  } catch (err) {
    return { success: false, message: 'Delete failed: ' + err.message };
  }
}

/**
 * Detect who is making the change (agent vs human).
 */
function detectActor() {
  // Check for Claude Code agent indicators
  if (process.env.CLAUDE_CODE) return 'agent:claude-code';
  if (process.env.CURSOR_SESSION) return 'agent:cursor';
  if (process.env.CODEX_SESSION) return 'agent:codex';
  if (!process.stdin.isTTY) return 'cli:script';
  return 'cli:human';
}

module.exports = {
  log,
  listChanges,
  getChange,
  undo,
  deleteEntry,
  purgeExpired,
  purgeAll,
  forcePurge,
  CHANGELOG_DIR,
};
