'use strict';

const fs = require('fs');
const path = require('path');
const cryptoLib = require('./crypto');
const { classify, suggestPlacement } = require('./classify');
const changelog = require('./changelog');

const STORE_DIR = path.join(cryptoLib.CRED_DIR, 'store');
const INDEX_PATH = path.join(STORE_DIR, 'index.json');
const VAULT_PATH = path.join(STORE_DIR, 'vault.age');
// Integrity sidecar: SHA-256 of the vault plaintext, refreshed on every write.
// Detects corruption, truncation, and rollback (an older valid vault.age swapped
// in) that plain age-decryption alone would not catch.
const VAULT_CHECKSUM_PATH = path.join(STORE_DIR, 'vault.sha256');

// ─── Index Management ───────────────────────────────────────────────────────

function ensureStoreDir() {
  if (!fs.existsSync(STORE_DIR)) {
    fs.mkdirSync(STORE_DIR, { recursive: true, mode: 0o700 });
  }
}

function loadIndex() {
  if (!fs.existsSync(INDEX_PATH)) {
    return createEmptyIndex();
  }
  return JSON.parse(fs.readFileSync(INDEX_PATH, 'utf8'));
}

// Atomic write: write to a temp file in the same dir, fsync-free rename over the
// target. Rename is atomic on the same filesystem, so a crash mid-write can never
// leave a half-written index/vault — the old file stays intact.
function atomicWrite(targetPath, data) {
  ensureStoreDir();
  const tmp = targetPath + '.tmp-' + process.pid + '-' + Date.now();
  fs.writeFileSync(tmp, data, { mode: 0o600 });
  fs.renameSync(tmp, targetPath);
}

function saveIndex(index) {
  ensureStoreDir();
  index.lastModified = new Date().toISOString();
  atomicWrite(INDEX_PATH, JSON.stringify(index, null, 2) + '\n');
}

function createEmptyIndex() {
  return {
    version: 1,
    lastModified: new Date().toISOString(),
    credentials: [],
    // A fresh vault starts with one project. Everything else is yours to add
    // (`credmgr projects add`). Earlier builds seeded this list with the
    // author's own projects, VPS users and deploy paths — that shipped one
    // person's infrastructure inventory to every user and is never coming back.
    projects: [
      { id: 'global', name: 'Global / Shared', vpsUser: null, deployPath: null, sshAlias: null },
    ],
    categories: [
      'server', 'wallet', 'rpc', 'api-key', 'database', 'supabase',
      'cloudflare', 'github', 'ssh-key', 'encryption-key', 'jwt-secret',
      'oauth', 'web-admin', 'cdn', 'analytics', 'ai-service', 'integration',
    ],
  };
}

// ─── Ref Number Management ──────────────────────────────────────────────────

/**
 * Generate a random 4-digit ref number (1000-9999) that doesn't collide
 * with any existing ref in the index. Refs are permanent — never reused.
 */
function randomRef(index) {
  const used = new Set();
  for (const c of index.credentials) {
    if (c.ref) used.add(c.ref);
  }
  // Also reserve refs from deleted credentials (tracked in deletedRefs)
  if (index.deletedRefs) {
    for (const r of index.deletedRefs) used.add(r);
  }
  let attempts = 0;
  while (attempts < 5000) {
    const ref = 1000 + Math.floor(Math.random() * 9000); // 1000-9999
    if (!used.has(ref)) return ref;
    attempts++;
  }
  // Fallback: find first unused number
  for (let n = 1000; n <= 9999; n++) {
    if (!used.has(n)) return n;
  }
  throw new Error('All 4-digit ref numbers exhausted');
}

/**
 * Check if a ref number is already in use by another credential.
 */
function isRefDuplicate(index, ref, excludeName) {
  return index.credentials.some(c => c.ref === ref && c.name !== excludeName);
}

/**
 * Ensure all credentials have a 4-digit ref number (backfill for existing store).
 * Migrates old sequential refs to random 4-digit ones.
 */
function ensureRefs(index) {
  let dirty = false;
  if (!index.deletedRefs) { index.deletedRefs = []; dirty = true; }
  for (const c of index.credentials) {
    if (!c.ref || c.ref < 1000) {
      c.ref = randomRef(index);
      dirty = true;
    }
  }
  if (dirty) saveIndex(index);
  return index;
}

/**
 * Find a credential by ref number.
 */
function getByRef(ref, opts, source) {
  const index = ensureRefs(loadIndex());
  const entry = index.credentials.find(c => c.ref === ref);
  if (!entry) return null;
  if (!opts) return { value: null, metadata: entry };
  const vault = loadVault(opts);
  try { logAccess(entry.name, source || 'cli'); } catch (_) {}
  return { value: vault[entry.id] || null, metadata: entry };
}

// ─── Vault Management ───────────────────────────────────────────────────────

function loadVault(opts) {
  if (!fs.existsSync(VAULT_PATH)) {
    return {};
  }
  const plaintext = cryptoLib.decryptFile(VAULT_PATH, opts);
  return JSON.parse(plaintext);
}

function saveVault(vault, opts) {
  ensureStoreDir();
  const plaintext = JSON.stringify(vault, null, 2);
  const encrypted = cryptoLib.encrypt(plaintext, opts);
  atomicWrite(VAULT_PATH, encrypted);
  // Refresh the integrity checksum (of the plaintext) alongside the ciphertext.
  atomicWrite(VAULT_CHECKSUM_PATH, cryptoLib.sha256(plaintext) + '\n');
}

/**
 * Verify the vault ciphertext matches its integrity checksum.
 * Returns { ok, status, expected, actual }.
 *   status: 'ok' | 'missing-checksum' | 'mismatch' | 'unreadable'
 * A missing checksum is treated as a soft warning (legacy vault predating the
 * sidecar) — call healStore/doctor to backfill it.
 */
function verifyVaultChecksum(opts) {
  if (!fs.existsSync(VAULT_CHECKSUM_PATH)) {
    return { ok: true, status: 'missing-checksum' };
  }
  let plaintext;
  try {
    plaintext = cryptoLib.decryptFile(VAULT_PATH, opts);
  } catch (e) {
    return { ok: false, status: 'unreadable', error: e.message };
  }
  const expected = fs.readFileSync(VAULT_CHECKSUM_PATH, 'utf8').trim();
  const actual = cryptoLib.sha256(plaintext);
  return { ok: expected === actual, status: expected === actual ? 'ok' : 'mismatch', expected, actual };
}

// ─── CRUD Operations ────────────────────────────────────────────────────────

// ─── Aliases (v1.8) ─────────────────────────────────────────────────────────
// An entry may carry `aliases: [{ name, fieldLabel|null }]` — the names it
// absorbed through merges (or manual assignment). Lookups resolve them
// transparently, so `credmgr get ACME_EVM_PRIVATE_KEY` keeps working
// after that credential was merged into a structured wallet entry: the alias's
// fieldLabel points at the specific field whose value the old name referred to.
// This is what makes vault restructuring safe for existing consumers.

function normalizeAliasSpec(a) {
  if (!a) return null;
  if (typeof a === 'string') {
    const n = a.trim();
    return n ? { name: n, fieldLabel: null } : null;
  }
  if (typeof a.name === 'string' && a.name.trim()) {
    return { name: a.name.trim(), fieldLabel: a.fieldLabel ? String(a.fieldLabel) : null };
  }
  return null;
}

function findByAlias(index, name) {
  for (const c of index.credentials) {
    if (!Array.isArray(c.aliases)) continue;
    const hit = c.aliases.find(a => a && a.name === name);
    if (hit) return { entry: c, fieldLabel: hit.fieldLabel || null };
  }
  return null;
}

// Resolve a name to its entry: exact name first, then alias.
function resolveEntry(index, name) {
  const direct = index.credentials.find(c => c.name === name);
  if (direct) return { entry: direct, fieldLabel: null, viaAlias: false };
  const alias = findByAlias(index, name);
  if (alias) return { entry: alias.entry, fieldLabel: alias.fieldLabel, viaAlias: true };
  return null;
}

// Pull one labelled field's value out of a structured (JSON _fields) blob.
function fieldValueFrom(raw, fieldLabel) {
  try {
    const parsed = JSON.parse(raw);
    if (parsed && Array.isArray(parsed._fields)) {
      const f = parsed._fields.find(x => x && x.label === fieldLabel);
      if (f && f.value != null) return String(f.value);
    }
  } catch (_) { /* flat value — no fields to address */ }
  return null;
}

// Throws if the proposed alias name collides with a live credential name or
// any other entry's alias. `excludeId` skips the entry the alias belongs to.
function assertAliasFree(index, aliasName, excludeId) {
  if (index.credentials.some(c => c.name === aliasName)) {
    throw new Error('Alias "' + aliasName + '" collides with an existing credential name');
  }
  for (const c of index.credentials) {
    if (c.id === excludeId || !Array.isArray(c.aliases)) continue;
    if (c.aliases.some(a => a && a.name === aliasName)) {
      throw new Error('Alias "' + aliasName + '" is already an alias of "' + c.name + '"');
    }
  }
}

/**
 * Get a credential value by name (aliases resolve transparently; an alias
 * with a fieldLabel returns THAT field's value from a structured entry).
 * Returns { value, metadata } or null if not found.
 */
function get(name, opts, source) {
  const index = loadIndex();
  const resolved = resolveEntry(index, name);
  if (!resolved) return null;
  const entry = resolved.entry;

  const vault = loadVault(opts);
  let value = vault[entry.id];
  if (value === undefined) return null;

  if (resolved.viaAlias && resolved.fieldLabel) {
    const fieldValue = fieldValueFrom(value, resolved.fieldLabel);
    if (fieldValue !== null) value = fieldValue;
  }

  try { logAccess(entry.name, source || 'cli'); } catch (_) {}
  const result = { value, metadata: entry };
  if (resolved.viaAlias) {
    result.resolvedFromAlias = name;
    if (resolved.fieldLabel) result.fieldLabel = resolved.fieldLabel;
  }
  return result;
}

/**
 * Get credential metadata only (no decryption needed).
 */
function getMetadata(name) {
  const index = loadIndex();
  return index.credentials.find(c => c.name === name) || null;
}

/**
 * Get credential by ID.
 */
function getById(id, opts) {
  const index = loadIndex();
  const entry = index.credentials.find(c => c.id === id);
  if (!entry) return null;

  const vault = loadVault(opts);
  const value = vault[entry.id];
  return { value: value || null, metadata: entry };
}

/**
 * Set (add or update) a credential.
 * Returns the credential metadata entry.
 */
function set(name, value, metaOverrides, opts) {
  const index = loadIndex();
  const vault = loadVault(opts);
  const existing = index.credentials.find(c => c.name === name);
  const now = new Date().toISOString();

  if (existing) {
    // Update existing
    const oldValue = vault[existing.id];
    const oldMeta = { ...existing };

    vault[existing.id] = value;
    existing.modified = now;

    if (metaOverrides) {
      if (metaOverrides.project) existing.project = metaOverrides.project;
      if (metaOverrides.category) existing.category = metaOverrides.category;
      if (metaOverrides.tags) existing.tags = metaOverrides.tags;
      if (metaOverrides.description) existing.description = metaOverrides.description;
      if (metaOverrides.sensitivity) existing.sensitivity = metaOverrides.sensitivity;
      if (metaOverrides.notes) existing.notes = metaOverrides.notes;
      if (metaOverrides.deployedTo) existing.deployedTo = metaOverrides.deployedTo;
      if (metaOverrides.expiresAt) existing.expiresAt = metaOverrides.expiresAt;
      if (metaOverrides.relatedIds) existing.relatedIds = metaOverrides.relatedIds;
      if (metaOverrides.url !== undefined) existing.url = metaOverrides.url;
    }

    saveVault(vault, opts);
    saveIndex(index);

    // Log the change
    changelog.log({
      action: 'modify',
      credentialId: existing.id,
      credentialName: name,
      previousValue: oldValue,
      newValue: value,
      previousMetadata: oldMeta,
    }, opts);

    return existing;
  } else {
    // Add new. A name that is currently someone's alias is refused — the two
    // would shadow each other and `get` results would depend on lookup order.
    const aliasOwner = findByAlias(index, name);
    if (aliasOwner) {
      throw new Error('"' + name + '" is an alias of "' + aliasOwner.entry.name +
        '" — update that credential, or remove the alias first');
    }
    const classification = suggestPlacement(name, index.credentials);
    const merged = { ...classification, ...(metaOverrides || {}) };

    const id = cryptoLib.randomId();
    if (!index.deletedRefs) index.deletedRefs = [];
    const entry = {
      id,
      ref: randomRef(index),
      name,
      project: merged.project || 'global',
      category: merged.category || 'api-key',
      tags: merged.tags || classification.tags || [],
      description: merged.description || '',
      created: now,
      modified: now,
      rotated: null,
      expiresAt: merged.expiresAt || null,
      sensitivity: merged.sensitivity || classification.sensitivity || 'medium',
      format: detectFormat(value),
      relatedIds: merged.relatedIds || [],
      deployedTo: merged.deployedTo || [],
      notes: merged.notes || '',
      url: merged.url || '',
      batchGroup: merged.batchGroup || null,
    };

    vault[id] = value;
    index.credentials.push(entry);

    // Ensure project exists
    if (!index.projects.find(p => p.id === entry.project)) {
      index.projects.push({
        id: entry.project,
        name: entry.project,
        vpsUser: null,
        deployPath: null,
        sshAlias: null,
      });
    }

    saveVault(vault, opts);
    saveIndex(index);

    changelog.log({
      action: 'add',
      credentialId: id,
      credentialName: name,
      previousValue: null,
      newValue: value,
      previousMetadata: null,
    }, opts);

    return entry;
  }
}

/**
 * Remove a credential (soft-delete: value preserved in changelog for 7 days).
 */
function remove(name, opts) {
  const index = loadIndex();
  const vault = loadVault(opts);
  const entryIdx = index.credentials.findIndex(c => c.name === name);

  if (entryIdx === -1) return false;

  const entry = index.credentials[entryIdx];
  const oldValue = vault[entry.id];

  // Log before removing
  changelog.log({
    action: 'delete',
    credentialId: entry.id,
    credentialName: name,
    previousValue: oldValue,
    newValue: null,
    previousMetadata: { ...entry },
  }, opts);

  // Track deleted ref so it's never reused
  if (!index.deletedRefs) index.deletedRefs = [];
  if (entry.ref && !index.deletedRefs.includes(entry.ref)) {
    index.deletedRefs.push(entry.ref);
  }

  // Remove from vault and index
  delete vault[entry.id];
  index.credentials.splice(entryIdx, 1);

  saveVault(vault, opts);
  saveIndex(index);

  return true;
}

/**
 * Rotate a credential (update value + set rotated timestamp).
 */
function rotate(name, newValue, opts) {
  const index = loadIndex();
  const entry = index.credentials.find(c => c.name === name);
  if (!entry) return null;

  const vault = loadVault(opts);
  const oldValue = vault[entry.id];
  const oldMeta = { ...entry };

  vault[entry.id] = newValue;
  entry.modified = new Date().toISOString();
  entry.rotated = new Date().toISOString();

  saveVault(vault, opts);
  saveIndex(index);

  changelog.log({
    action: 'rotate',
    credentialId: entry.id,
    credentialName: name,
    previousValue: oldValue,
    newValue: newValue,
    previousMetadata: oldMeta,
  }, opts);

  return entry;
}

// ─── Search & List ──────────────────────────────────────────────────────────

/**
 * List all credentials (metadata only, no decryption).
 */
function list(filters) {
  const index = ensureRefs(loadIndex());
  let results = index.credentials;

  if (filters) {
    if (filters.project) {
      results = results.filter(c => c.project === filters.project);
    }
    if (filters.category) {
      results = results.filter(c => c.category === filters.category);
    }
    if (filters.tag) {
      results = results.filter(c => c.tags && c.tags.includes(filters.tag));
    }
    if (filters.sensitivity) {
      results = results.filter(c => c.sensitivity === filters.sensitivity);
    }
  }

  return results;
}

/**
 * Fuzzy search across name, description, tags, project, category, notes.
 */
function search(query) {
  const index = loadIndex();
  const q = query.toLowerCase();
  const terms = q.split(/\s+/).filter(t => t.length > 0);

  const scored = index.credentials.map(cred => {
    let score = 0;
    const aliasNames = (cred.aliases || []).map(a => a && a.name).filter(Boolean);
    const searchable = [
      cred.name,
      cred.description,
      cred.project,
      cred.category,
      cred.notes,
      ...(cred.tags || []),
      ...(cred.deployedTo || []),
      ...aliasNames,
    ].filter(Boolean).join(' ').toLowerCase();

    for (const term of terms) {
      // Exact name match (highest weight) — aliases count as names
      if (cred.name.toLowerCase() === q) score += 100;
      if (aliasNames.some(a => a.toLowerCase() === q)) score += 90;
      // Name contains term
      if (cred.name.toLowerCase().includes(term)) score += 10;
      if (aliasNames.some(a => a.toLowerCase().includes(term))) score += 9;
      // Other fields contain term
      if (searchable.includes(term)) score += 5;
      // Tag exact match
      if (cred.tags && cred.tags.some(t => t === term)) score += 8;
    }

    return { ...cred, _score: score };
  });

  return scored
    .filter(c => c._score > 0)
    .sort((a, b) => b._score - a._score)
    .map(({ _score, ...cred }) => cred);
}

/**
 * List all projects.
 */
function listProjects() {
  const index = loadIndex();
  return index.projects;
}

/**
 * Export credentials for a project as KEY=VALUE lines (.env format).
 */
function exportEnv(project, opts, o) {
  const index = loadIndex();
  const vault = loadVault(opts);
  const creds = index.credentials.filter(c => c.project === project);
  const includeAliases = !!(o && o.includeAliases);

  const envLine = (name, value) => {
    const needsQuotes = /[#\s'"\\\n\r$`!]/.test(value);
    return needsQuotes ? `${name}='${value.replace(/'/g, "'\\''")}'` : `${name}=${value}`;
  };

  const lines = [];
  for (const cred of creds) {
    const value = vault[cred.id];
    if (value === undefined) continue;
    lines.push(envLine(cred.name, value));
    // Both spellings, behind the flag: an alias with a fieldLabel exports
    // that field's value (the old flat name's exact meaning); without one it
    // exports the whole value — same as `credmgr get <alias>`.
    if (includeAliases && Array.isArray(cred.aliases)) {
      for (const a of cred.aliases) {
        if (!a || !a.name) continue;
        const fieldValue = a.fieldLabel ? fieldValueFrom(value, a.fieldLabel) : null;
        lines.push(envLine(a.name, fieldValue !== null ? fieldValue : value));
      }
    }
  }

  return lines.join('\n') + '\n';
}

/**
 * Get store statistics.
 */
function stats() {
  const index = loadIndex();
  const byProject = {};
  const byCategory = {};
  const bySensitivity = {};

  for (const cred of index.credentials) {
    byProject[cred.project] = (byProject[cred.project] || 0) + 1;
    byCategory[cred.category] = (byCategory[cred.category] || 0) + 1;
    bySensitivity[cred.sensitivity] = (bySensitivity[cred.sensitivity] || 0) + 1;
  }

  return {
    total: index.credentials.length,
    byProject,
    byCategory,
    bySensitivity,
    projectCount: index.projects.length,
    lastModified: index.lastModified,
  };
}

/**
 * Update metadata for a credential (no value change).
 */
function updateMetadata(name, updates, opts) {
  const index = loadIndex();
  const entry = index.credentials.find(c => c.name === name);
  if (!entry) return null;

  const oldMeta = { ...entry };

  if (updates.project !== undefined) entry.project = updates.project;
  if (updates.category !== undefined) entry.category = updates.category;
  if (updates.tags !== undefined) entry.tags = updates.tags;
  if (updates.description !== undefined) entry.description = updates.description;
  if (updates.sensitivity !== undefined) entry.sensitivity = updates.sensitivity;
  if (updates.notes !== undefined) entry.notes = updates.notes;
  if (updates.deployedTo !== undefined) entry.deployedTo = updates.deployedTo;
  if (updates.expiresAt !== undefined) entry.expiresAt = updates.expiresAt;
  if (updates.relatedIds !== undefined) entry.relatedIds = updates.relatedIds;
  if (updates.url !== undefined) entry.url = updates.url;
  if (updates.name !== undefined && updates.name !== entry.name) {
    const newName = String(updates.name).trim();
    if (!newName) throw new Error('Name cannot be empty');
    if (index.credentials.some(c => c.name === newName && c.id !== entry.id)) {
      throw new Error('A credential named "' + newName + '" already exists');
    }
    const aliasOwner = findByAlias(index, newName);
    if (aliasOwner && aliasOwner.entry.id !== entry.id) {
      throw new Error('"' + newName + '" is an alias of "' + aliasOwner.entry.name + '"');
    }
    // Renaming to one of the entry's OWN aliases: drop that alias (the name
    // is being promoted back to the primary). Other aliases survive the
    // rename untouched — they live on the entry, not on the name.
    if (Array.isArray(entry.aliases)) {
      entry.aliases = entry.aliases.filter(a => a && a.name !== newName);
    }
    entry.name = newName;
  }
  if (updates.aliases !== undefined) {
    const specs = (Array.isArray(updates.aliases) ? updates.aliases : [])
      .map(normalizeAliasSpec).filter(Boolean);
    const seen = new Set();
    for (const spec of specs) {
      if (seen.has(spec.name)) throw new Error('Duplicate alias "' + spec.name + '"');
      seen.add(spec.name);
      if (spec.name === entry.name) throw new Error('An alias cannot equal the credential\'s own name');
      assertAliasFree(index, spec.name, entry.id);
    }
    entry.aliases = specs;
  }
  if (updates.ref !== undefined) {
    const newRef = parseInt(updates.ref, 10);
    if (isNaN(newRef) || newRef < 1000 || newRef > 9999) {
      throw new Error('Ref must be a 4-digit number (1000-9999)');
    }
    if (isRefDuplicate(index, newRef, entry.name)) {
      throw new Error('Ref #' + newRef + ' is already in use');
    }
    entry.ref = newRef;
  }
  entry.modified = new Date().toISOString();

  // Update the encrypted value if provided
  let oldValue = null;
  let newValue = null;
  if (updates.value !== undefined) {
    const vault = loadVault(opts);
    oldValue = vault[entry.id];
    vault[entry.id] = updates.value;
    newValue = updates.value;
    entry.format = detectFormat(updates.value);
    saveVault(vault, opts);
  }

  saveIndex(index);

  changelog.log({
    action: updates.value !== undefined ? 'modify' : 'metadata-update',
    credentialId: entry.id,
    credentialName: name,
    previousValue: oldValue,
    newValue: newValue,
    previousMetadata: oldMeta,
  }, opts);

  return entry;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function detectFormat(value) {
  if (!value) return 'empty';
  try { var p = JSON.parse(value); if (p && Array.isArray(p._fields)) return 'structured'; } catch (_) {}
  if (/^0x[a-fA-F0-9]{64}$/.test(value)) return 'hex-key';
  if (/^0x[a-fA-F0-9]{40}$/.test(value)) return 'eth-address';
  if (value.startsWith('sk-') || value.startsWith('sk_')) return 'api-key';
  if (value.startsWith('ghp_') || value.startsWith('github_pat_')) return 'github-pat';
  if (value.startsWith('eyJ')) return 'jwt';
  if (value.startsWith('AGE-SECRET-KEY-')) return 'age-key';
  if (value.startsWith('ssh-')) return 'ssh-public-key';
  if (value.includes('BEGIN') && value.includes('PRIVATE KEY')) return 'pem-key';
  if (value.startsWith('https://')) return 'url';
  if (/^[a-fA-F0-9]{32,}$/.test(value)) return 'hex-secret';
  if (value.includes(' ') && value.split(' ').length >= 12) return 'mnemonic';
  return 'password';
}

/**
 * Verify vault integrity end-to-end:
 *  - vault ciphertext matches its plaintext checksum (corruption/rollback)
 *  - every index entry has a vault value, and vice-versa (no orphans)
 *  - no two active credentials share a ref, and no active ref is also in
 *    deletedRefs (the "ref never reused" contract)
 */
function verifyIntegrity(opts) {
  const index = loadIndex();
  const errors = [];
  const warnings = [];

  // Decrypt ONCE and reuse the plaintext for both the checksum comparison and
  // the parsed vault (previously this decrypted twice — two age spawns).
  // A corrupt/undecryptable vault must produce a clean FAIL report, never an
  // uncaught age error.
  let plaintext = null;
  let vault = null;
  let vaultError = null;
  try {
    if (fs.existsSync(VAULT_PATH)) {
      plaintext = cryptoLib.decryptFile(VAULT_PATH, opts);
      vault = JSON.parse(plaintext);
    } else {
      vault = {};
    }
  } catch (e) {
    vaultError = e.message;
    errors.push('Vault could not be decrypted: ' + e.message);
  }

  // 1. Checksum (against the already-decrypted plaintext)
  let chk;
  if (vaultError) {
    chk = { status: 'unreadable', error: vaultError };
  } else if (!fs.existsSync(VAULT_CHECKSUM_PATH)) {
    chk = { status: 'missing-checksum' };
    warnings.push('No integrity checksum yet (legacy vault) — run: credmgr doctor --fix');
  } else if (plaintext === null) {
    chk = { status: 'mismatch' };
    errors.push('Checksum exists but vault.age is missing');
  } else {
    const expected = fs.readFileSync(VAULT_CHECKSUM_PATH, 'utf8').trim();
    const actual = cryptoLib.sha256(plaintext);
    chk = { status: expected === actual ? 'ok' : 'mismatch' };
    if (chk.status === 'mismatch') {
      errors.push('Vault checksum mismatch — vault.age does not match vault.sha256 (corruption or rollback)');
    }
  }

  // 2. Index <-> vault consistency (only if the vault decrypted)
  if (vault) for (const cred of index.credentials) {
    if (vault[cred.id] === undefined) {
      errors.push(`Credential "${cred.name}" (${cred.id}) missing from vault`);
    }
  }
  if (vault) {
    const indexIds = new Set(index.credentials.map(c => c.id));
    for (const vaultId of Object.keys(vault)) {
      if (!indexIds.has(vaultId)) {
        errors.push(`Vault entry "${vaultId}" has no matching index entry (orphaned)`);
      }
    }
  }

  // 3. Ref integrity
  const seenRefs = new Map();
  const deleted = new Set(index.deletedRefs || []);
  for (const cred of index.credentials) {
    if (!cred.ref) { warnings.push(`Credential "${cred.name}" has no ref number`); continue; }
    if (seenRefs.has(cred.ref)) {
      errors.push(`Ref #${cred.ref} used by both "${seenRefs.get(cred.ref)}" and "${cred.name}"`);
    } else {
      seenRefs.set(cred.ref, cred.name);
    }
    if (deleted.has(cred.ref)) {
      warnings.push(`Ref #${cred.ref} ("${cred.name}") is also in deletedRefs (resurrected ref)`);
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    checksum: chk.status,
    credentialCount: index.credentials.length,
  };
}

// ─── Heal / Doctor ──────────────────────────────────────────────────────────

/**
 * Detect and repair store inconsistencies. Non-destructive to credential values.
 *  - Backfills the integrity checksum if missing.
 *  - Resolves resurrected refs (active ref also in deletedRefs) by cleaning the
 *    deletedRefs list — the active credential is the source of truth.
 *  - Reassigns a fresh ref to any credential that collides with another active
 *    credential (keeps the older/lower id, re-refs the newer).
 *  - Backfills any missing ref.
 *  - Registers any category used by a credential but absent from the registry.
 * Returns a report of what was fixed. Pass { apply:false } for a dry run.
 */
function healStore(opts, healOpts) {
  const apply = !healOpts || healOpts.apply !== false;
  const index = loadIndex();
  const fixes = [];
  if (!index.deletedRefs) index.deletedRefs = [];

  // 1. Resurrected refs: an active ref must not sit in deletedRefs.
  const activeRefs = new Set(index.credentials.map(c => c.ref).filter(Boolean));
  const cleanedDeleted = index.deletedRefs.filter(r => !activeRefs.has(r));
  if (cleanedDeleted.length !== index.deletedRefs.length) {
    const removed = index.deletedRefs.filter(r => activeRefs.has(r));
    fixes.push({ type: 'resurrected-refs', detail: `Removed ${removed.length} active ref(s) from deletedRefs: ${removed.join(', ')}` });
    index.deletedRefs = cleanedDeleted;
  }

  // 2. Duplicate active refs: re-ref the later credential.
  const seen = new Map();
  for (const cred of index.credentials) {
    if (cred.ref && seen.has(cred.ref)) {
      const oldRef = cred.ref;
      cred.ref = randomRef(index);
      activeRefs.add(cred.ref);
      fixes.push({ type: 'duplicate-ref', detail: `"${cred.name}" collided on #${oldRef} → reassigned #${cred.ref}` });
    } else if (cred.ref) {
      seen.set(cred.ref, cred.name);
    }
  }

  // 3. Missing refs.
  for (const cred of index.credentials) {
    if (!cred.ref) {
      cred.ref = randomRef(index);
      activeRefs.add(cred.ref);
      fixes.push({ type: 'missing-ref', detail: `Assigned #${cred.ref} to "${cred.name}"` });
    }
  }

  // 4. Unregistered categories.
  const known = new Set(index.categories || []);
  const used = new Set(index.credentials.map(c => c.category).filter(Boolean));
  for (const cat of used) {
    if (!known.has(cat)) {
      index.categories.push(cat);
      known.add(cat);
      fixes.push({ type: 'unregistered-category', detail: `Registered category "${cat}"` });
    }
  }

  if (apply && fixes.length > 0) saveIndex(index);

  // 5. Backfill checksum (needs vault access).
  let checksumFixed = false;
  if (apply && !fs.existsSync(VAULT_CHECKSUM_PATH)) {
    try {
      const vault = loadVault(opts);
      saveVault(vault, opts); // rewrites vault + fresh checksum sidecar
      checksumFixed = true;
      fixes.push({ type: 'checksum', detail: 'Backfilled vault integrity checksum' });
    } catch (_) { /* no vault access in dry contexts */ }
  }

  return { applied: apply, fixCount: fixes.length, fixes, checksumFixed };
}

// ─── Password / Token Generation ────────────────────────────────────────────

/**
 * Generate a cryptographically-random secret.
 * @param {object} o
 *   length   - number of characters (default 32)
 *   type     - 'password' (mixed set) | 'alnum' | 'hex' | 'base64url' (default 'password')
 *   symbols  - include symbols for 'password' type (default true)
 */
function generateSecret(o) {
  const opts = o || {};
  const length = Math.max(1, Math.min(4096, opts.length || 32));
  const nodeCrypto = require('crypto');

  if (opts.type === 'hex') return nodeCrypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
  if (opts.type === 'base64url') return nodeCrypto.randomBytes(length).toString('base64url').slice(0, length);

  const lower = 'abcdefghijkmnpqrstuvwxyz';       // no l
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';        // no I, O
  const digits = '23456789';                       // no 0, 1
  const symbols = '!@#$%^&*()-_=+[]{}';
  let alphabet = lower + upper + digits;
  if (opts.type !== 'alnum' && opts.symbols !== false) alphabet += symbols;

  // Rejection sampling for unbiased selection across the alphabet.
  const out = [];
  const max = 256 - (256 % alphabet.length);
  while (out.length < length) {
    for (const byte of nodeCrypto.randomBytes(length * 2)) {
      if (byte < max) { out.push(alphabet[byte % alphabet.length]); if (out.length === length) break; }
    }
  }
  return out.join('');
}

// ─── .env Import ─────────────────────────────────────────────────────────────

/**
 * Parse KEY=VALUE lines (dotenv-ish) and import them. Skips comments/blank lines.
 * Values already present with the SAME value are skipped as duplicates; present
 * with a DIFFERENT value are reported as conflicts and NOT overwritten unless
 * o.overwrite is set. Returns { imported, skipped, conflicts, names }.
 */
function importEnv(content, metaOverrides, opts, o) {
  const overwrite = o && o.overwrite;
  const index = loadIndex();
  const vault = loadVault(opts);
  const byName = new Map(index.credentials.map(c => [c.name, c]));

  const report = { imported: [], skipped: [], conflicts: [] };
  const lines = content.split(/\r?\n/);
  for (let raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    let name = line.slice(0, eq).trim().replace(/^export\s+/, '');
    let value = line.slice(eq + 1).trim();
    // Strip matching surrounding quotes.
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!name) continue;

    const existing = byName.get(name);
    if (existing) {
      const cur = vault[existing.id];
      if (cur === value) { report.skipped.push(name); continue; }
      if (!overwrite) { report.conflicts.push(name); continue; }
    }
    set(name, value, metaOverrides || null, opts);
    report.imported.push(name);
  }
  return {
    imported: report.imported.length,
    skipped: report.skipped.length,
    conflicts: report.conflicts.length,
    names: report,
  };
}

// ─── Batch Import (flat + multi-field / wallet records) ─────────────────────

// Wallet shorthand keys → structured _fields, in a canonical display order.
// A "batch of wallets" upload sends one object per wallet with these keys;
// each becomes ONE structured credential (address + privateKey + seedPhrase +
// … as sub-credentials), never a flat blob and never scattered entries.
const WALLET_FIELD_MAP = [
  ['chain', 'chain'],
  ['walletType', 'walletType'],
  ['address', 'address'],
  ['publicKey', 'publicKey'],
  ['privateKey', 'privateKey'],
  ['seedPhrase', 'seedPhrase'],
  ['derivationPath', 'derivationPath'],
  ['xpub', 'xpub'],
  ['zpub', 'zpub'],
  ['purpose', 'purpose'],
];
const WALLET_SEED_ALIASES = ['seedPhrase', 'seed', 'mnemonic', 'recoveryPhrase'];

function buildWalletFields(item) {
  const fields = [];
  for (const [key, label] of WALLET_FIELD_MAP) {
    if (item[key] != null && String(item[key]).length) {
      fields.push({ label, value: String(item[key]) });
    }
  }
  // Fold any seed-phrase alias into a single canonical seedPhrase field.
  if (!fields.some(f => f.label === 'seedPhrase')) {
    for (const a of WALLET_SEED_ALIASES) {
      if (item[a] != null && String(item[a]).length) {
        fields.push({ label: 'seedPhrase', value: String(item[a]) });
        break;
      }
    }
  }
  return fields;
}

function isWalletShaped(item) {
  return WALLET_FIELD_MAP.some(([k]) => item[k] != null) ||
         WALLET_SEED_ALIASES.some(a => item[a] != null);
}

// ─── Daemon / Agent Auth Token ─────────────────────────────────────────────
// The same bearer token `credmgr serve` and the MCP server check (CREDMGR_TOKEN).
// Lives under CREDMGR_DIR (CREDMGR_HOME-aware) so sandbox runs never touch a
// real installation's token. Revoking it is the real "disable agent access"
// switch: lib/server.js's auth middleware rejects every /api/* call once no
// valid token is presented.
function daemonTokenPath(opts) {
  return (opts && opts.daemonTokenPath) || path.join(cryptoLib.CREDMGR_DIR, 'daemon.token');
}
function getDaemonToken(opts) {
  try { return fs.readFileSync(daemonTokenPath(opts), 'utf8').trim() || null; }
  catch (_) { return null; }
}
function rotateDaemonToken(opts) {
  const token = require('crypto').randomBytes(32).toString('hex');
  fs.mkdirSync(path.dirname(daemonTokenPath(opts)), { recursive: true, mode: 0o700 });
  fs.writeFileSync(daemonTokenPath(opts), token, { mode: 0o600 });
  return token;
}
function revokeDaemonToken(opts) {
  const p = daemonTokenPath(opts);
  if (fs.existsSync(p)) fs.unlinkSync(p);
}

/**
 * Import a batch of credentials. Each item becomes EXACTLY ONE credential:
 *   • { name, value }                            → flat credential
 *   • { name, fields:[{label,value}] }           → one structured entry (sub-credentials)
 *   • { name, address, privateKey, seedPhrase }  → one structured wallet entry (shorthand)
 *
 * Never flattens a whole batch into a single entry, and never scatters one
 * record's fields across separate entries — a wallet is one entry with its
 * address/privateKey/seedPhrase as sub-credentials. Dedupe-aware: identical
 * values are skipped, differing values are conflicts unless o.overwrite.
 *
 * @param {Array<object>} items
 * @param {object} o     { batchGroup?, overwrite?, defaultProject?, dryRun? }
 * @param {object} opts  crypto opts
 *
 * dryRun runs the exact same classification/dedupe logic (so counts are a
 * true preview) but never calls `set()` — nothing is written to the vault.
 */
function batchImport(items, o, opts) {
  const bo = o || {};
  const overwrite = !!bo.overwrite;
  const dryRun = !!bo.dryRun;
  const index = loadIndex();
  const vault = loadVault(opts);
  const byName = new Map(index.credentials.map(c => [c.name, c]));
  const batchGroup = (bo.batchGroup && String(bo.batchGroup).trim()) ||
    ('batch-' + new Date().toISOString().slice(0, 10) + '-' + cryptoLib.randomId(3));

  const results = [], failures = [], skipped = [], conflicts = [];

  for (const item of (Array.isArray(items) ? items : [])) {
    try {
      if (!item || !item.name) { failures.push({ name: item && item.name, error: 'name is required' }); continue; }
      const name = String(item.name);

      let value, kind, defaultCategory, sensitive = false;
      if (Array.isArray(item.fields) && item.fields.length) {
        const fields = item.fields
          .filter(f => f && f.label != null && f.value != null && String(f.value).length)
          .map(f => ({ label: String(f.label), value: String(f.value) }));
        if (!fields.length) { failures.push({ name, error: 'fields[] present but all empty' }); continue; }
        value = JSON.stringify({ _fields: fields });
        kind = 'structured';
        sensitive = fields.some(f => /priv|seed|mnemonic|secret/i.test(f.label));
      } else if (isWalletShaped(item)) {
        const fields = buildWalletFields(item);
        if (!fields.length) { failures.push({ name, error: 'wallet item has no usable fields' }); continue; }
        value = JSON.stringify({ _fields: fields });
        kind = 'wallet';
        defaultCategory = 'wallet';
        sensitive = fields.some(f => f.label === 'privateKey' || f.label === 'seedPhrase');
      } else if (item.value != null && String(item.value).length) {
        value = String(item.value);
        kind = 'flat';
      } else {
        failures.push({ name, error: 'item needs value, fields[], or wallet keys (address/privateKey/seedPhrase)' });
        continue;
      }

      const existing = byName.get(name);
      if (existing) {
        if (vault[existing.id] === value) { skipped.push(name); continue; }
        if (!overwrite) { conflicts.push(name); continue; }
      }

      const baseTags = Array.isArray(item.tags) ? item.tags.slice() : [];
      if (!baseTags.includes(batchGroup)) baseTags.push(batchGroup);
      const meta = {
        project: item.project || bo.defaultProject,
        category: item.category || defaultCategory,
        tags: baseTags,
        description: item.description,
        notes: item.notes,
        url: item.url,
        sensitivity: item.sensitivity || (sensitive ? 'critical' : undefined),
        batchGroup,
      };
      Object.keys(meta).forEach(k => meta[k] === undefined && delete meta[k]);

      if (dryRun) {
        results.push({
          name, ref: existing ? existing.ref : null, project: meta.project, kind,
          fields: kind === 'flat' ? undefined : JSON.parse(value)._fields.length,
          wouldOverwrite: !!existing,
        });
        continue;
      }

      const entry = set(name, value, meta, opts);
      // Keep local caches fresh so a repeated name within the same batch dedupes.
      byName.set(name, entry);
      vault[entry.id] = value;
      results.push({ name: entry.name, ref: entry.ref, project: entry.project, kind, fields: kind === 'flat' ? undefined : JSON.parse(value)._fields.length });
    } catch (err) {
      failures.push({ name: item && item.name, error: err.message });
    }
  }

  return {
    added: results.length,
    skipped: skipped.length,
    conflicts: conflicts.length,
    errors: failures.length,
    batchGroup,
    results,
    failures,
    skippedNames: skipped,
    conflictNames: conflicts,
    dryRun,
  };
}

// ─── Encrypted Backup ────────────────────────────────────────────────────────

/**
 * Create a portable age-encrypted tar snapshot of the store.
 * @param {object} o  { outPath?, includeKey? }
 * Returns { path, items, includeKey }. Shared by the CLI and the HTTP API.
 */
function backup(o, opts) {
  const { execFileSync } = require('child_process');
  const bo = o || {};
  const stamp = new Date().toISOString().slice(0, 10);
  const outPath = bo.outPath || path.join(cryptoLib.CRED_DIR, 'backups', 'credmgr-backup-' + stamp + '.tar.age');

  const dir = path.dirname(outPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  const items = ['store/index.json', 'store/vault.age'];
  if (fs.existsSync(VAULT_CHECKSUM_PATH)) items.push('store/vault.sha256');
  if (bo.includeKey) {
    items.push('.credmgr/master.key', '.credmgr/master.pub', '.credmgr/config.json');
  }
  const existing = items.filter(i => fs.existsSync(path.join(cryptoLib.CRED_DIR, i)));

  const tmp = cryptoLib.secureTempFile('backup.tar', '');
  try {
    execFileSync('tar', ['-cf', tmp.file, '-C', cryptoLib.CRED_DIR, ...existing]);
    // Raw Buffer — binary-safe.
    cryptoLib.encryptToFile(fs.readFileSync(tmp.file), outPath, opts);
  } finally {
    cryptoLib.cleanupTemp(tmp.dir);
  }

  // Retention: prune the oldest backups beyond `retain` (default 14). Only
  // files matching our own naming scheme are candidates — a manually renamed
  // backup is never touched. retain:0 disables pruning.
  const retain = bo.retain != null ? parseInt(bo.retain, 10) : 14;
  let pruned = [];
  if (Number.isFinite(retain) && retain > 0) {
    const all = fs.readdirSync(dir)
      .filter(f => /^credmgr-backup-\d{4}-\d{2}-\d{2}\.tar\.age$/.test(f))
      .sort(); // date-stamped names sort chronologically
    const excess = all.length - retain;
    if (excess > 0) {
      for (const f of all.slice(0, excess)) {
        try {
          fs.unlinkSync(path.join(dir, f));
          pruned.push(f);
        } catch { /* leave unremovable files in place */ }
      }
    }
  }

  return { path: outPath, items: existing, includeKey: !!bo.includeKey, retain, pruned };
}

// ─── Per-Credential Version History ─────────────────────────────────────────

/**
 * Return the change history for a single credential (newest first), derived
 * from the encrypted changelog. Values are redacted unless o.includeValues.
 */
function history(name, opts, o) {
  const meta = getMetadata(name);
  const all = changelog.listChanges(opts);
  const rows = all.filter(c => c.credentialName === name || (meta && c.credentialId === meta.id));
  return rows.map(c => ({
    changeId: c.changeId,
    timestamp: c.timestamp,
    action: c.action,
    actor: c.actor,
    previousValue: o && o.includeValues ? c.previousValue : (c.previousValue ? '[redacted]' : null),
    newValue: o && o.includeValues ? c.newValue : (c.newValue ? '[redacted]' : null),
  }));
}

// ─── Merge ─────────────────────────────────────────────────────────────────

/**
 * Merge multiple credentials into one structured credential.
 * @param {string[]} sourceNames - names of credentials to merge
 * @param {string} newName - name for the consolidated credential
 * @param {Array<{label:string, value:string}>} fields - structured fields
 * @param {object} metaOverrides - project, category, sensitivity, etc.
 * @param {object} opts - crypto opts
 * @returns {{ merged: object, archived: string[] }}
 */
function merge(sourceNames, newName, fields, metaOverrides, opts) {
  // Load fresh index to read source metadata before any mutations
  const freshIndex = loadIndex();

  // Build structured value
  const structuredValue = JSON.stringify({ _fields: fields });

  // Determine highest sensitivity from sources.
  // NOTE: use a hasOwnProperty-safe rank — `sensOrder[x] || 3` would misrank
  // 'critical' (0 is falsy) as the LOWEST severity.
  const sensOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const sensRank = s => (sensOrder[s] !== undefined ? sensOrder[s] : 3);
  let maxSens = 'low';
  for (const name of sourceNames) {
    const entry = freshIndex.credentials.find(c => c.name === name);
    if (entry && sensRank(entry.sensitivity) < sensRank(maxSens)) {
      maxSens = entry.sensitivity;
    }
  }

  // Collect tags from all sources
  const allTags = new Set();
  for (const name of sourceNames) {
    const entry = freshIndex.credentials.find(c => c.name === name);
    if (entry && entry.tags) entry.tags.forEach(t => allTags.add(t));
  }

  const merged = metaOverrides || {};
  // Optional precise alias→field mapping from autoMerge (name → final label).
  // Pulled out before `merged` reaches set() — it's not credential metadata.
  const aliasLabels = merged._aliasLabels || null;
  delete merged._aliasLabels;
  // Sensitivity: never below the highest source level; an explicit override
  // may only raise it further (e.g. auto-merge upgrading wallets to critical).
  if (!merged.sensitivity || sensRank(merged.sensitivity) > sensRank(maxSens)) {
    merged.sensitivity = maxSens;
  }
  if (!merged.tags) merged.tags = Array.from(allTags);

  // Collect source refs before archiving (we'll need them for the chosen ref)
  const sourceRefs = {};
  for (const name of sourceNames) {
    const entry = freshIndex.credentials.find(c => c.name === name);
    if (entry) sourceRefs[name] = entry.ref;
  }

  // Create the new merged credential
  const newEntry = set(newName, structuredValue, merged, opts);

  // Archive (soft-delete) the source credentials FIRST, so a ref inherited
  // from a source is free again before we claim it (no transient duplicate,
  // no "resurrected ref" warning).
  const archived = [];
  for (const name of sourceNames) {
    if (name === newName) continue; // don't delete the target if it's being updated
    const removed = remove(name, opts);
    if (removed) archived.push(name);
  }

  // Apply the chosen ref (from metaOverrides.ref or a source)
  if (merged.ref) {
    const idx = loadIndex();
    const created = idx.credentials.find(c => c.name === newName);
    const chosenRef = parseInt(merged.ref, 10);
    const takenByOther = idx.credentials.some(c => c.ref === chosenRef && c.name !== newName);
    if (created && chosenRef >= 1000 && chosenRef <= 9999 && !takenByOther) {
      created.ref = chosenRef;
      // The chosen ref usually came from an archived source — reclaim it from
      // deletedRefs so the store stays consistent ("active ref never deleted").
      idx.deletedRefs = (idx.deletedRefs || []).filter(r => r !== chosenRef);
      saveIndex(idx);
      newEntry.ref = chosenRef;
    }
  }

  // v1.8 aliases: every archived source name becomes an alias of the merged
  // entry, so existing consumers (`credmgr get OLD_NAME`, exports) keep
  // working after the restructure. Field mapping: the precise map from
  // autoMerge when provided, else the name's own type suffix if that label
  // exists among the merged fields. Aliases the sources had themselves are
  // carried over too (ancestry survives repeated merges).
  {
    const idx = loadIndex();
    const target = idx.credentials.find(c => c.name === newName);
    if (target) {
      const labelSet = new Set(fields.map(f => f.label));
      target.aliases = Array.isArray(target.aliases) ? target.aliases : [];
      const taken = new Set(target.aliases.map(a => a && a.name).filter(Boolean));
      const liveNames = new Set(idx.credentials.map(c => c.name));

      const addAlias = (aliasName, fieldLabel) => {
        if (!aliasName || taken.has(aliasName) || liveNames.has(aliasName)) return;
        target.aliases.push({ name: aliasName, fieldLabel: fieldLabel || null });
        taken.add(aliasName);
      };

      for (const srcName of archived) {
        const srcEntry = freshIndex.credentials.find(c => c.name === srcName);
        if (srcEntry && Array.isArray(srcEntry.aliases)) {
          for (const a of srcEntry.aliases) {
            if (a && a.name) addAlias(a.name, a.fieldLabel && labelSet.has(a.fieldLabel) ? a.fieldLabel : null);
          }
        }
        let label = aliasLabels && Object.prototype.hasOwnProperty.call(aliasLabels, srcName)
          ? aliasLabels[srcName]
          : (() => { const s = splitNameStem(srcName); return s && s.known ? s.fieldLabel : null; })();
        if (label && !labelSet.has(label)) label = null;
        addAlias(srcName, label);
      }
      saveIndex(idx);
      newEntry.aliases = target.aliases;
    }
  }

  return { merged: newEntry, archived };
}

// ─── Auto-Merge ─────────────────────────────────────────────────────────────

/**
 * Automatically merge a set of credentials into ONE structured credential
 * with clearly labelled fields — no manual field mapping required.
 *
 *  • Flat sources contribute one field each; the label is derived from the
 *    name's type suffix (ACME_Email_USER → username, ACME_EMAIL_PASS →
 *    password, "test wallet 1 private key" → privateKey).
 *  • Structured sources contribute all of their existing fields.
 *  • Identical label+value pairs are de-duplicated; the same label with a
 *    DIFFERENT value gets a numbered label (password, password_2) so no
 *    data is ever silently dropped.
 *  • The merged entry keeps the lowest source ref, the union of source tags,
 *    and at least the highest source sensitivity (wallet secrets → critical).
 *  • Sources are then soft-deleted (recoverable via the changelog for 7 days).
 *
 * @param {string[]} sourceNames
 * @param {object} o     { newName?, project?, category?, description?, ref? }
 * @param {object} opts  crypto opts
 * @returns {{ merged, archived, fields: [{label}] }}
 */
function autoMerge(sourceNames, o, opts) {
  const ao = o || {};
  if (!Array.isArray(sourceNames) || sourceNames.length < 2) {
    throw new Error('auto-merge needs at least 2 source credentials');
  }
  const index = loadIndex();
  const vault = loadVault(opts);
  const entries = [];
  for (const name of sourceNames) {
    const entry = index.credentials.find(c => c.name === name);
    if (!entry) throw new Error('Credential "' + name + '" not found');
    entries.push(entry);
  }

  // Build the combined field list. aliasLabels records, per FLAT source, the
  // final label its value ended up under — so the alias created for that
  // source name can point at exactly that field (v1.8). Structured sources
  // map to null: their old name referred to the whole entry.
  const fields = [];
  const aliasLabels = {};
  const seenPairs = new Set();   // label(lower)+value → dedupe identical data
  const usedLabels = new Set();  // label(lower) → disambiguate collisions
  for (const entry of entries) {
    const raw = vault[entry.id];
    if (raw === undefined || raw === null) continue;
    let sourceFields;
    let isFlat = false;
    let parsed = null;
    try { parsed = JSON.parse(raw); } catch (_) { /* flat value */ }
    if (parsed && Array.isArray(parsed._fields)) {
      sourceFields = parsed._fields
        .filter(f => f && f.label != null && f.value != null)
        .map(f => ({ label: String(f.label), value: String(f.value) }));
    } else {
      // Prefer the name's type suffix; when the name gives no KNOWN suffix,
      // blend in what the VALUE looks like (0x{64} → privateKey, 12 lowercase
      // words → seedPhrase, m/44'/… → derivationPath, …). Blend, not replace:
      // an unknown suffix's raw last token (e.g. "BTC"/"LTC"/"LIGHTNING" off
      // "…_XPUB_BTC") is exactly what told near-identical names apart, and
      // the value-shape detector alone can't see it — every xpub-shaped
      // value detects as the same generic 'xpub' regardless of chain. Losing
      // that token is how 13 chain-specific xpubs used to collapse into one
      // merged record with 13 same-named, indistinguishable fields.
      const split = splitNameStem(entry.name);
      let label = split ? split.fieldLabel : 'value';
      if (!split || !split.known) {
        const detected = detectFieldLabelFromValue(raw);
        if (detected) {
          const bare = split && split.fieldLabel;
          label = (bare && bare !== 'value' && detected.toLowerCase() !== bare.toLowerCase())
            ? detected + '_' + bare
            : detected;
        }
      }
      sourceFields = [{ label, value: String(raw) }];
      isFlat = true;
    }
    for (const f of sourceFields) {
      const pairKey = f.label.toLowerCase() + '\u0000' + f.value;
      if (seenPairs.has(pairKey)) {
        // exact duplicate — kept once; the alias for this source still points
        // at the field that already holds this value
        if (isFlat) {
          const existing = fields.find(x => x.value === f.value);
          aliasLabels[entry.name] = existing ? existing.label : null;
        }
        continue;
      }
      seenPairs.add(pairKey);
      let label = f.label;
      if (usedLabels.has(label.toLowerCase())) {
        let n = 2;
        while (usedLabels.has((f.label + '_' + n).toLowerCase())) n++;
        label = f.label + '_' + n;
      }
      usedLabels.add(label.toLowerCase());
      fields.push({ label, value: f.value });
      if (isFlat) aliasLabels[entry.name] = label;
    }
    if (!isFlat && aliasLabels[entry.name] === undefined) {
      aliasLabels[entry.name] = null; // structured source → alias to whole entry
    }
  }
  if (!fields.length) throw new Error('No field values could be extracted from the sources');

  const baseLabel = l => l.replace(/_\d+$/, '');
  const walletLike = new Set(
    fields.map(f => baseLabel(f.label)).filter(l => WALLET_FIELD_LABELS.indexOf(l) !== -1)
  ).size >= 2;
  const hasCriticalPart = fields.some(f => /^(privateKey|seedPhrase)(_\d+)?$/.test(f.label));

  const newName = (ao.newName && String(ao.newName).trim()) || commonStem(sourceNames) || entries[0].name;
  const refs = entries.map(e => e.ref).filter(Boolean).sort((a, b) => a - b);
  const category = ao.category || (walletLike ? 'wallet' : entries[0].category);

  // Schema-aware column order: a merged wallet always reads chain → address
  // → publicKey → privateKey → seedPhrase → derivationPath → accountIndex…
  const ordered = orderFieldsBySchema(fields, category);

  const meta = {
    project: ao.project || entries[0].project,
    category,
    description: ao.description || ('Auto-merged from: ' + sourceNames.join(', ')),
    ref: ao.ref || refs[0] || undefined,
    _aliasLabels: aliasLabels, // precise alias→field map; consumed by merge()
  };
  if (hasCriticalPart) meta.sensitivity = 'critical';

  const result = merge(sourceNames, newName, ordered, meta, opts);
  return { merged: result.merged, archived: result.archived, fields: ordered.map(f => ({ label: f.label })) };
}

/**
 * Batch auto-merge: run the suggestion engine and auto-merge every group
 * that is SAFE to merge without human review. Safe means:
 *   • the group is wallet-shaped (walletLike), OR
 *   • every member's name has a KNOWN type suffix (username/password/apiKey…)
 * Groups with unknown/ambiguous suffixes are skipped and reported — they need
 * the per-group review UI. Exact-duplicate suggestions are never touched here
 * (deleting data is a human decision).
 *
 * @param {object} o    { dryRun?: boolean }
 * @param {object} opts crypto opts
 * @returns {{ planned, merged, skipped, errors }}
 */
function autoMergeAll(o, opts) {
  const ao = o || {};
  const dryRun = !!ao.dryRun;
  const suggestions = findMergeSuggestions(opts);

  const planned = [], skipped = [], merged = [], errors = [];
  for (const s of suggestions) {
    if (s.type !== 'merge-candidates') continue;
    const allKnown = s.names.every(n => {
      const split = splitNameStem(n);
      return split && split.known;
    });
    const safe = s.walletLike || allKnown;
    if (!safe) {
      skipped.push({ names: s.names, stem: s.stem, reason: 'ambiguous field labels — review manually' });
      continue;
    }
    planned.push({ newName: s.suggestedName, names: s.names, walletLike: !!s.walletLike });
    if (dryRun) continue;
    try {
      const r = autoMerge(s.names, { newName: s.suggestedName, category: s.suggestedCategory }, opts);
      merged.push({ newName: r.merged.name, ref: r.merged.ref, sources: s.names, fields: r.fields.map(f => f.label) });
    } catch (err) {
      errors.push({ names: s.names, error: err.message });
    }
  }
  return { dryRun, planned, merged, skipped, errors };
}

// ─── Project Rename ────────────────────────────────────────────────────────

/**
 * Rename a project's display name. The id (slug) is immutable — only the
 * human-readable name in index.projects changes.
 */
function renameProject(projectId, newName) {
  if (!projectId || !newName || !newName.trim()) {
    throw new Error('projectId and newName are required');
  }
  const index = loadIndex();
  const proj = index.projects.find(p => p.id === projectId);
  if (!proj) throw new Error('Project "' + projectId + '" not found');
  proj.name = newName.trim();
  saveIndex(index);
  return proj;
}

/**
 * Remove a project so it no longer appears as a selectable/taggable option
 * (dashboard dropdown, `credmgr projects`, `--project=` filters). This is
 * for finishing a teardown: once every credential that used to live under a
 * retired project has been reassigned or removed, the project's own label
 * should stop being offered — otherwise a retired project keeps reappearing
 * in the tagging UI forever, which is exactly the confusion this exists to
 * prevent. Refuses if any credential still references the project (reassign
 * or remove those first — this never silently orphans data) or if it's
 * `global` (the one project that must always exist).
 */
function removeProject(projectId) {
  if (!projectId) throw new Error('projectId is required');
  if (projectId === 'global') throw new Error('The global project cannot be removed');
  const index = loadIndex();
  const proj = index.projects.find(p => p.id === projectId);
  if (!proj) throw new Error('Project "' + projectId + '" not found');
  const stillUsed = index.credentials.filter(c => c.project === projectId);
  if (stillUsed.length > 0) {
    throw new Error(
      'Project "' + projectId + '" still has ' + stillUsed.length +
      ' credential(s) assigned to it — reassign or remove them first: ' +
      stillUsed.slice(0, 5).map(c => c.name).join(', ') + (stillUsed.length > 5 ? ', …' : '')
    );
  }
  index.projects = index.projects.filter(p => p.id !== projectId);
  saveIndex(index);
  return { removed: true, projectId, name: proj.name };
}

/**
 * Move every credential currently assigned to `fromProjectId` onto
 * `toProjectId`. Used from the dashboard to consolidate stale projects
 * (e.g. a project that was renamed but whose credentials still point at
 * the old ID, or merging a small project into "global").
 *
 * Returns { fromProjectId, toProjectId, moved, names }.
 */
function reassignProject(fromProjectId, toProjectId, opts) {
  if (!fromProjectId || !toProjectId) {
    throw new Error('fromProjectId and toProjectId are required');
  }
  if (fromProjectId === toProjectId) {
    throw new Error('Source and destination project must differ');
  }
  const index = loadIndex();
  const toProj = index.projects.find(p => p.id === toProjectId);
  if (!toProj) throw new Error('Destination project "' + toProjectId + '" not found');

  const moved = [];
  const now = new Date().toISOString();
  for (const cred of index.credentials) {
    if (cred.project === fromProjectId) {
      const before = { ...cred };
      cred.project = toProjectId;
      cred.modified = now;
      moved.push(cred.name);
      changelog.log({
        action: 'metadata-update',
        credentialId: cred.id,
        credentialName: cred.name,
        previousMetadata: before,
      }, opts);
    }
  }
  saveIndex(index);
  return { fromProjectId, toProjectId, moved: moved.length, names: moved };
}

// ─── Name Tokenization + Field-Label Mapping ────────────────────────────────
// Shared by the suggestion engine and auto-merge so a suggestion's preview and
// the merge it produces can never disagree about what a name part "means".

// UPPERCASE token sequences (joined by '_') → canonical structured-field label.
// Longest suffix wins: "TEST_WALLET_1_PUBLIC_KEY" → stem TEST_WALLET_1 + publicKey.
const FIELD_LABEL_MAP = {
  'PUBLIC_KEY': 'publicKey', 'PUB_KEY': 'publicKey', 'PUBKEY': 'publicKey', 'PUBLIC': 'publicKey', 'PUB': 'publicKey',
  'PRIVATE_KEY': 'privateKey', 'PRIV_KEY': 'privateKey', 'PRIVKEY': 'privateKey', 'PRIVATE': 'privateKey', 'PRIV': 'privateKey',
  'SEED_PHRASE': 'seedPhrase', 'SEEDPHRASE': 'seedPhrase', 'SEED': 'seedPhrase', 'MNEMONIC': 'seedPhrase',
  'RECOVERY_PHRASE': 'seedPhrase', 'PHRASE': 'seedPhrase',
  'ADDRESS': 'address', 'ADDR': 'address', 'WALLET_ADDRESS': 'address',
  'USER': 'username', 'USERNAME': 'username', 'USER_NAME': 'username', 'LOGIN': 'username', 'ACCOUNT': 'username',
  'EMAIL': 'email', 'MAIL': 'email',
  'PASS': 'password', 'PASSWORD': 'password', 'PASS_WORD': 'password', 'PWD': 'password',
  'API_KEY': 'apiKey', 'APIKEY': 'apiKey', 'KEY': 'key',
  'API_SECRET': 'apiSecret', 'SECRET': 'secret', 'SECRET_KEY': 'secretKey',
  'TOKEN': 'token', 'ACCESS_TOKEN': 'accessToken', 'REFRESH_TOKEN': 'refreshToken', 'AUTH': 'auth',
  'URL': 'url', 'URI': 'url', 'ENDPOINT': 'url', 'HOST': 'host', 'IP': 'host', 'PORT': 'port',
  'ID': 'id', 'CLIENT_ID': 'clientId', 'PROJECT_ID': 'projectId', 'ZONE_ID': 'zoneId',
  'DATABASE': 'database', 'DB': 'database',
  'XPUB': 'xpub', 'ZPUB': 'zpub', 'DERIVATION_PATH': 'derivationPath',
  'ACCOUNT_INDEX': 'accountIndex', 'SUB_WALLET': 'accountIndex', 'SUBWALLET': 'accountIndex',
  'WALLET_INDEX': 'accountIndex', 'INDEX': 'accountIndex',
  'CHAIN': 'chain', 'NETWORK': 'chain', 'RPC_URL': 'url', 'RPC': 'url',
  'WEBHOOK': 'webhook', 'DSN': 'dsn', 'CERT': 'cert', 'PEM': 'pem',
};
const WALLET_FIELD_LABELS = ['publicKey', 'privateKey', 'seedPhrase', 'address', 'xpub', 'zpub', 'derivationPath', 'accountIndex'];
const MAX_SUFFIX_TOKENS = 3;

// ─── Type Schemas ("columns" per item type) ────────────────────────────────
// A structured credential's `_fields` ARE its columns. Schemas make that
// explicit per category: the canonical column set, its display/merge order,
// which columns are required to call the record complete, and which are
// secrets that force critical sensitivity. Schemas drive:
//   • auto-merge field ordering (wallet always reads chain → address →
//     publicKey → privateKey → seedPhrase → derivationPath → accountIndex…)
//   • missing-column detection (audit + the dashboard's "add field" chips)
//   • the Add form's type presets (served via GET /api/schemas)
// Adding a new multi-column item type = adding one entry here.
const TYPE_SCHEMAS = {
  wallet: {
    label: 'Wallet',
    fields: ['chain', 'walletType', 'address', 'publicKey', 'privateKey', 'seedPhrase',
             'derivationPath', 'accountIndex', 'xpub', 'zpub', 'purpose'],
    // A wallet is "complete" with at least one locator + one secret.
    requiredAny: [['address', 'publicKey', 'xpub', 'zpub'], ['privateKey', 'seedPhrase']],
    criticalFields: ['privateKey', 'seedPhrase'],
  },
  server: {
    label: 'VPS / Server',
    fields: ['host', 'port', 'username', 'password', 'sshKey', 'url', 'notes'],
    requiredAny: [['host', 'url']],
    criticalFields: ['sshKey'],
  },
  database: {
    label: 'Database',
    fields: ['host', 'port', 'username', 'password', 'database', 'url'],
    requiredAny: [['host', 'url']],
    criticalFields: [],
  },
  'api-key': {
    label: 'API service',
    fields: ['apiKey', 'apiSecret', 'token', 'clientId', 'url', 'accountId'],
    requiredAny: [['apiKey', 'apiSecret', 'token', 'key', 'secret']],
    criticalFields: [],
  },
  'web-admin': {
    label: 'Web login',
    fields: ['url', 'username', 'email', 'password'],
    requiredAny: [['username', 'email']],
    criticalFields: [],
  },
  oauth: {
    label: 'OAuth app',
    fields: ['clientId', 'secret', 'accessToken', 'refreshToken', 'url'],
    requiredAny: [['clientId', 'accessToken']],
    criticalFields: [],
  },
};

function schemaForCategory(category) {
  return TYPE_SCHEMAS[category] || null;
}

/**
 * Order structured fields by their schema position (unknown labels keep
 * their relative order after the schema-known ones). Numbered collision
 * labels (privateKey_2) sort right after their base column.
 */
function orderFieldsBySchema(fields, category) {
  const schema = schemaForCategory(category);
  if (!schema) return fields;
  const rank = {};
  schema.fields.forEach((f, i) => { rank[f.toLowerCase()] = i; });
  const base = l => String(l).replace(/_\d+$/, '').toLowerCase();
  return fields
    .map((f, i) => ({ f, i }))
    .sort((a, b) => {
      const ra = rank[base(a.f.label)] !== undefined ? rank[base(a.f.label)] : 1000 + a.i;
      const rb = rank[base(b.f.label)] !== undefined ? rank[base(b.f.label)] : 1000 + b.i;
      return ra !== rb ? ra - rb : a.i - b.i;
    })
    .map(x => x.f);
}

/**
 * Which schema columns is this structured value missing?
 * Returns { missingRequired: [group…], suggested: [label…] } or null when
 * the category has no schema. `suggested` = schema columns not yet present
 * (drives the dashboard's one-click "add column" chips).
 */
function missingSchemaFields(category, fields) {
  const schema = schemaForCategory(category);
  if (!schema) return null;
  const have = new Set(fields.map(f => String(f.label).replace(/_\d+$/, '').toLowerCase()));
  const missingRequired = [];
  for (const group of (schema.requiredAny || [])) {
    if (!group.some(l => have.has(l.toLowerCase()))) missingRequired.push(group);
  }
  const suggested = schema.fields.filter(l => !have.has(l.toLowerCase()));
  return { missingRequired, suggested };
}

/**
 * Best-effort field label from the VALUE's shape — used when a name gives
 * no usable label (auto-merge fallback) and to sanity-label pasted data.
 */
function detectFieldLabelFromValue(value) {
  const v = String(value == null ? '' : value).trim();
  if (!v) return null;
  if (/^0x[a-fA-F0-9]{64}$/.test(v)) return 'privateKey';
  if (/^0x[a-fA-F0-9]{40}$/.test(v)) return 'address';
  if (/^(xpub|ypub|zpub|tpub)[1-9A-HJ-NP-Za-km-z]{20,}$/.test(v)) return v.slice(0, 4) === 'zpub' ? 'zpub' : 'xpub';
  if (/^m(\/\d+'?)+$/.test(v)) return 'derivationPath';
  if (/^(bc1|ltc1)[a-z0-9]{20,}$/.test(v) || /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(v)) return 'address';
  const words = v.split(/\s+/);
  if ((words.length === 12 || words.length === 15 || words.length === 18 || words.length === 24) &&
      words.every(w => /^[a-z]+$/.test(w))) return 'seedPhrase';
  if (/^-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(v)) return 'sshKey';
  if (/^ssh-(rsa|ed25519|ecdsa)/.test(v)) return 'publicKey';
  if (/^https?:\/\//.test(v)) return 'url';
  if (v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'email'; // length cap: no polynomial backtracking on a long value
  return null;
}

function tokenizeCredName(name) {
  return String(name || '').split(/[\s_\-./]+/).filter(Boolean);
}

/**
 * Split a credential name into { stem, suffix, fieldLabel, known }.
 * Matches the longest known type suffix (up to 3 trailing tokens, case-
 * insensitive, across space/underscore/dash separators); falls back to the
 * last token. Returns null for single-token names (no separable stem).
 */
function splitNameStem(name) {
  const tokens = tokenizeCredName(name);
  if (tokens.length < 2) return null;
  for (let k = Math.min(MAX_SUFFIX_TOKENS, tokens.length - 1); k >= 1; k--) {
    const suffix = tokens.slice(tokens.length - k).join('_').toUpperCase();
    if (FIELD_LABEL_MAP[suffix]) {
      return {
        stem: tokens.slice(0, tokens.length - k).join('_'),
        suffix,
        fieldLabel: FIELD_LABEL_MAP[suffix],
        known: true,
      };
    }
  }
  const last = tokens[tokens.length - 1].toUpperCase();
  return {
    stem: tokens.slice(0, -1).join('_'),
    suffix: last,
    fieldLabel: last.toLowerCase(),
    known: false,
  };
}

/** Canonical field label for a whole credential name (used for flat sources). */
function fieldLabelForName(name) {
  const split = splitNameStem(name);
  return split ? split.fieldLabel : 'value';
}

/** Longest common token-prefix across names → 'STEM_AS_NAME' (uppercased). */
function commonStem(names) {
  if (!names || !names.length) return '';
  const tokenLists = names.map(n => tokenizeCredName(n).map(t => t.toUpperCase()));
  const minLen = Math.min(...tokenLists.map(t => t.length));
  const common = [];
  for (let i = 0; i < minLen; i++) {
    const t = tokenLists[0][i];
    if (tokenLists.every(list => list[i] === t)) common.push(t);
    else break;
  }
  return common.join('_');
}

// ─── Smart Merge/Duplicate Suggestions ────────────────────────────────────

/**
 * Analyse the vault and index to produce actionable merge suggestions.
 *
 * Returns two types of suggestion:
 *   { type:'exact-duplicate', names, keepName, duplicates, reason }
 *   { type:'merge-candidates', names, stem, suggestedName, suggestedFields,
 *     reason, project }
 *
 * Requires decrypted vault access (opts) for exact-duplicate detection.
 * merge-candidates are detected from index metadata alone (no decryption).
 *
 * @param {object} [listOpts] { includeDismissed?: boolean } — pass
 *   includeDismissed:true for a Settings "manage dismissed" view; default
 *   (false) hides groups the user already reviewed and rejected.
 */
function findMergeSuggestions(opts, listOpts) {
  const index = loadIndex();
  const creds = index.credentials;
  const suggestions = [];

  // ── 1. Exact duplicates (same vault value) ─────────────────────────────
  // 1b. Near-duplicate values (v1.8 / 4.3): identical after normalizing
  // trim/quotes/trailing newline — one is almost certainly a sloppy paste of
  // the other. Review-only: whitespace CAN be significant (PEM blocks), so
  // deletion is never suggested automatically.
  if (opts) {
    let vault;
    try { vault = loadVault(opts); } catch (_) { vault = null; }
    if (vault) {
      const valueMap = {}; // canonicalised value → [{name, id}]
      const normMap = {};  // normalized value → [{name, id, raw}]
      const normalizeValue = (v) => {
        let s = String(v).trim();
        if ((s.startsWith('"') && s.endsWith('"') && s.length >= 2) ||
            (s.startsWith("'") && s.endsWith("'") && s.length >= 2)) {
          s = s.slice(1, -1).trim();
        }
        return s;
      };
      for (const c of creds) {
        const val = vault[c.id];
        if (!val || typeof val !== 'string' || val.length < 6) continue;
        const key = val.trim();
        if (!valueMap[key]) valueMap[key] = [];
        valueMap[key].push({ name: c.name, id: c.id });
        const nkey = normalizeValue(val);
        if (nkey.length >= 6) {
          if (!normMap[nkey]) normMap[nkey] = [];
          normMap[nkey].push({ name: c.name, id: c.id, raw: key });
        }
      }
      for (const [, entries] of Object.entries(valueMap)) {
        if (entries.length >= 2) {
          // Keep the entry with the lowest ref (oldest)
          const sorted = [...entries].sort((a, b) => {
            const ra = creds.find(c => c.id === a.id);
            const rb = creds.find(c => c.id === b.id);
            return (ra ? ra.ref : 9999) - (rb ? rb.ref : 9999);
          });
          suggestions.push({
            type: 'exact-duplicate',
            severity: 'high',
            names: sorted.map(e => e.name),
            keepName: sorted[0].name,
            duplicates: sorted.slice(1).map(e => e.name),
            reason: `These ${sorted.length} credentials have identical values. The duplicates can be safely removed.`,
          });
        }
      }
      for (const [, entries] of Object.entries(normMap)) {
        if (entries.length < 2) continue;
        // Same normalized value but NOT all the same raw value — otherwise
        // the exact-duplicate suggestion above already covers the group.
        const distinctRaw = new Set(entries.map(e => e.raw));
        if (distinctRaw.size < 2) continue;
        suggestions.push({
          type: 'near-duplicate-value',
          severity: 'medium',
          names: entries.map(e => e.name),
          reason: `These ${entries.length} values are identical except for whitespace/quotes — ` +
            'likely the same secret pasted differently. Review which spelling is canonical.',
        });
      }
    }
  }

  // ── 2. Related credentials (same service/wallet stem) ──────────────────
  // Tokenize on space/underscore/dash/dot, match the longest known type
  // suffix (multi-word suffixes included: "PUBLIC KEY", "SEED PHRASE", …),
  // and group by the remaining stem CASE-INSENSITIVELY. So:
  //   "ACME_Email_USER" + "ACME_EMAIL_PASS"          → one ACME_EMAIL group
  //   "test wallet 1 public key" / "… private key" /
  //   "… seed phrase"                              → one TEST_WALLET_1 group
  //   (wallet 2 / wallet 3 each form their own group — the number is stem)
  const groups = {}; // stemKey (UPPER) → { stem, members: [{name,suffix,fieldLabel,ref}] }

  for (const c of creds) {
    // Skip already-structured (merged) credentials
    if (c.format === 'structured') continue;
    const split = splitNameStem(c.name);
    if (!split || split.stem.replace(/[_\W]/g, '').length < 2) continue;
    const key = split.stem.toUpperCase();
    if (!groups[key]) groups[key] = { stem: split.stem, members: [] };
    groups[key].members.push({
      name: c.name,
      suffix: split.suffix,
      fieldLabel: split.fieldLabel,
      ref: c.ref || null,
    });
  }

  for (const key of Object.keys(groups)) {
    const stem = groups[key].stem;
    const members = groups[key].members;
    if (members.length < 2) continue;

    const credObjs = members.map(m => creds.find(c => c.name === m.name)).filter(Boolean);
    const projs = [...new Set(credObjs.map(c => c.project))];

    // Wallet-shaped groups: stem mentions "wallet" or ≥2 distinct wallet fields.
    const walletFieldCount = new Set(
      members.map(m => m.fieldLabel).filter(l => WALLET_FIELD_LABELS.indexOf(l) !== -1)
    ).size;
    const walletLike = /(^|_)WALLETS?(_|$)/.test(key) || walletFieldCount >= 2;
    const hasCriticalPart = members.some(m => m.fieldLabel === 'privateKey' || m.fieldLabel === 'seedPhrase');

    suggestions.push({
      type: 'merge-candidates',
      severity: (walletLike && hasCriticalPart) ? 'high' : members.length >= 3 ? 'medium' : 'low',
      names: members.map(m => m.name),
      stem,
      projects: projs,
      walletLike,
      suggestedName: key,
      suggestedCategory: walletLike ? 'wallet' : undefined,
      suggestedFields: members.map(m => ({ label: m.fieldLabel, name: m.name, ref: m.ref })),
      reason: walletLike
        ? `${members.length} credentials look like the parts of one wallet ("${stem}") — merge into a single wallet entry.`
        : `${members.length} credentials share the "${stem}" stem and likely belong to the same service.`,
    });
  }

  // ── 3. Near-name matches (v1.8 / 4.2) ──────────────────────────────────
  // Exact-stem grouping misses UPTIMEROBOT vs UPTIME_ROBOT_MAIN (different
  // stems) and SENTRY_DNS vs SENTRY_DSN (typo). Normalize harder — drop
  // separators and filler tokens — then compare collapsed stems by equality,
  // prefix, token-set overlap, and edit distance. Review-only: never fed to
  // autoMergeAll (which only consumes type === 'merge-candidates').
  {
    const FILLER = /^(MAIN|NEW|OLD|FULL|V\d+|\d+|VPS\d*)$/;
    const flat = creds.filter(c => c.format !== 'structured');
    const items = flat.map(c => {
      const split = splitNameStem(c.name);
      const stem = split ? split.stem : c.name;
      const tokens = tokenizeCredName(stem).map(t => t.toUpperCase()).filter(t => !FILLER.test(t));
      return {
        name: c.name,
        stemKey: (split ? split.stem : c.name).toUpperCase(),
        tokens,
        collapsed: tokens.join(''),
      };
    }).filter(it => it.collapsed.length >= 5);

    const levenshtein = (a, b) => {
      if (Math.abs(a.length - b.length) > 2) return 3; // early out — we only care about ≤2
      const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
      for (let j = 1; j <= b.length; j++) dp[0][j] = j;
      for (let i = 1; i <= a.length; i++) {
        for (let j = 1; j <= b.length; j++) {
          dp[i][j] = Math.min(
            dp[i - 1][j] + 1,
            dp[i][j - 1] + 1,
            dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
          );
        }
      }
      return dp[a.length][b.length];
    };

    const overlapCoefficient = (a, b) => {
      if (!a.length || !b.length) return 0;
      const setA = new Set(a);
      let inter = 0;
      for (const t of b) if (setA.has(t)) inter++;
      return inter / Math.min(a.length, new Set(b).size);
    };

    // Union-find over pairwise matches
    const parent = items.map((_, i) => i);
    const find = (x) => (parent[x] === x ? x : (parent[x] = find(parent[x])));
    const union = (a, b) => { parent[find(a)] = find(b); };

    for (let i = 0; i < items.length; i++) {
      for (let j = i + 1; j < items.length; j++) {
        const A = items[i], B = items[j];
        if (A.stemKey === B.stemKey) continue; // exact-stem groups already cover these
        const near =
          A.collapsed === B.collapsed ||
          (A.collapsed.length >= 6 && B.collapsed.length >= 6 &&
            (A.collapsed.startsWith(B.collapsed) || B.collapsed.startsWith(A.collapsed))) ||
          overlapCoefficient(A.tokens, B.tokens) >= 0.8 ||
          (Math.min(A.collapsed.length, B.collapsed.length) >= 8 &&
            levenshtein(A.collapsed, B.collapsed) <= 2);
        if (near) union(i, j);
      }
    }

    const clusters = {};
    items.forEach((it, i) => {
      const root = find(i);
      if (!clusters[root]) clusters[root] = [];
      clusters[root].push(it);
    });
    for (const members of Object.values(clusters)) {
      if (members.length < 2) continue;
      const distinctStems = new Set(members.map(m => m.stemKey));
      if (distinctStems.size < 2) continue; // all one stem — covered above
      suggestions.push({
        type: 'near-name',
        severity: 'low',
        names: members.map(m => m.name),
        stems: [...distinctStems],
        reason: `These ${members.length} names look like variants of the same thing ` +
          `(${[...distinctStems].join(' / ')}) — possibly a typo pair or a MAIN/OLD/V2 spelling drift. Review before merging.`,
      });
    }
  }

  // Stable key per suggestion (type + sorted member names) so a dismissal
  // survives the group being recomputed fresh on every call — this is what
  // dismissSuggestion()/the dismissed-filter below key off of.
  for (const s of suggestions) s.key = suggestionKey(s.type, s.names);

  const dismissed = loadIndex().dismissedSuggestions || {};
  const visible = (listOpts && listOpts.includeDismissed)
    ? suggestions
    : suggestions.filter(s => !dismissed[s.key]);

  // Sort: high first, then medium, then low; within tier by group size desc
  return visible.sort((a, b) => {
    const sev = { high: 0, medium: 1, low: 2 };
    const sd = (sev[a.severity] || 3) - (sev[b.severity] || 3);
    return sd !== 0 ? sd : b.names.length - a.names.length;
  });
}

function suggestionKey(type, names) {
  return type + ':' + JSON.stringify(names.slice().sort());
}

/**
 * Persist that the user reviewed and rejected a suggested merge/dedupe
 * group, so it stops reappearing every time findMergeSuggestions recomputes
 * — the scan itself has no memory of past decisions; this is that memory.
 * `key` must be the exact `.key` a suggestion was returned with (see
 * suggestionKey above), not something the caller reconstructs — a bad
 * reconstruction would silently dismiss the wrong group or nothing at all.
 */
function dismissSuggestion(key) {
  if (!key || typeof key !== 'string') throw new Error('dismissSuggestion needs a suggestion key');
  const index = loadIndex();
  if (!index.dismissedSuggestions) index.dismissedSuggestions = {};
  index.dismissedSuggestions[key] = { dismissedAt: new Date().toISOString() };
  saveIndex(index);
  return { dismissed: true, key };
}

/** Undo a dismissal — the group reappears next time suggestions are listed. */
function undismissSuggestion(key) {
  const index = loadIndex();
  if (index.dismissedSuggestions && index.dismissedSuggestions[key]) {
    delete index.dismissedSuggestions[key];
    saveIndex(index);
    return { restored: true, key };
  }
  return { restored: false, key };
}

/** All currently-dismissed suggestion keys, for a Settings "manage" view. */
function listDismissedSuggestions() {
  const map = loadIndex().dismissedSuggestions || {};
  return Object.keys(map)
    .map(key => ({ key, dismissedAt: map[key].dismissedAt }))
    .sort((a, b) => (a.dismissedAt < b.dismissedAt ? 1 : -1));
}

/** Bulk-undo every dismissal — every dismissed group reappears on next scan. */
function restoreAllDismissedSuggestions() {
  const index = loadIndex();
  const count = index.dismissedSuggestions ? Object.keys(index.dismissedSuggestions).length : 0;
  index.dismissedSuggestions = {};
  saveIndex(index);
  return { restored: count };
}

// ─── Access Log ────────────────────────────────────────────────────────────

const ACCESS_LOG_PATH = path.join(cryptoLib.CREDMGR_DIR, 'access.json');
const ACCESS_LOG_MAX = 1000;

function logAccess(credName, source) {
  let log = [];
  try { log = JSON.parse(fs.readFileSync(ACCESS_LOG_PATH, 'utf8')); } catch (_) {}
  log.push({ name: credName, source: source || 'cli', ts: new Date().toISOString() });
  if (log.length > ACCESS_LOG_MAX) log = log.slice(log.length - ACCESS_LOG_MAX);
  fs.writeFileSync(ACCESS_LOG_PATH, JSON.stringify(log, null, 2) + '\n', { mode: 0o600 });
}

function getAccessLog(filters) {
  let log = [];
  try { log = JSON.parse(fs.readFileSync(ACCESS_LOG_PATH, 'utf8')); } catch (_) {}
  if (filters) {
    if (filters.name) log = log.filter(e => e.name === filters.name);
    if (filters.source) log = log.filter(e => e.source === filters.source);
    if (filters.limit) log = log.slice(-filters.limit);
  }
  return log.reverse();
}

// Empty the access log. Returns the number of records removed.
function purgeAccessLog() {
  let count = 0;
  try { count = JSON.parse(fs.readFileSync(ACCESS_LOG_PATH, 'utf8')).length; } catch (_) {}
  fs.writeFileSync(ACCESS_LOG_PATH, '[]\n', { mode: 0o600 });
  return count;
}

// ─── Expiration Alerts ─────────────────────────────────────────────────────

function expiring(daysAhead) {
  const index = loadIndex();
  const now = new Date();
  const horizon = new Date(now.getTime() + (daysAhead || 7) * 86400000);
  const results = [];

  for (const cred of index.credentials) {
    if (!cred.expiresAt) continue;
    const exp = new Date(cred.expiresAt);
    if (exp <= horizon) {
      const daysLeft = Math.ceil((exp - now) / 86400000);
      results.push({ ...cred, daysLeft, expired: daysLeft <= 0 });
    }
  }

  return results.sort((a, b) => a.daysLeft - b.daysLeft);
}

// ─── Health Audit ──────────────────────────────────────────────────────────

function audit(opts) {
  const index = loadIndex();
  const vault = opts ? loadVault(opts) : null;
  const issues = [];

  // Check for missing descriptions
  for (const cred of index.credentials) {
    if (!cred.description && !cred.notes) {
      issues.push({ type: 'no-description', severity: 'low', name: cred.name,
        message: 'No description or notes set' });
    }
  }

  // Check for stale credentials (not rotated in 90+ days)
  const staleThreshold = new Date(Date.now() - 90 * 86400000);
  for (const cred of index.credentials) {
    const lastTouch = new Date(cred.rotated || cred.modified || cred.created);
    if (lastTouch < staleThreshold) {
      const days = Math.floor((Date.now() - lastTouch.getTime()) / 86400000);
      issues.push({ type: 'stale', severity: 'medium', name: cred.name,
        message: 'Not rotated in ' + days + ' days' });
    }
  }

  // Check for expired credentials
  const now = new Date();
  for (const cred of index.credentials) {
    if (cred.expiresAt && new Date(cred.expiresAt) < now) {
      issues.push({ type: 'expired', severity: 'high', name: cred.name,
        message: 'Expired on ' + cred.expiresAt.slice(0, 10) });
    }
  }

  // Check for duplicate values (if vault available)
  if (vault) {
    const valueMap = {};
    for (const cred of index.credentials) {
      const val = vault[cred.id];
      if (!val || val.length < 8) continue;
      if (valueMap[val]) {
        issues.push({ type: 'duplicate-value', severity: 'high', name: cred.name,
          message: 'Same value as ' + valueMap[val] });
      } else {
        valueMap[val] = cred.name;
      }
    }

    // Check for weak passwords
    for (const cred of index.credentials) {
      if (cred.format !== 'password') continue;
      const val = vault[cred.id];
      if (!val) continue;
      if (val.length < 12) {
        issues.push({ type: 'weak-password', severity: 'medium', name: cred.name,
          message: 'Password shorter than 12 characters' });
      } else if (!/[A-Z]/.test(val) || !/[0-9]/.test(val) || !/[^a-zA-Z0-9]/.test(val)) {
        issues.push({ type: 'weak-password', severity: 'low', name: cred.name,
          message: 'Password missing uppercase, digit, or special char' });
      }
    }

    // Structured records missing required schema columns (e.g. a wallet with
    // a private key but no address/public key, a server with no host)
    for (const cred of index.credentials) {
      const val = vault[cred.id];
      if (!val) continue;
      let parsed = null;
      try { parsed = JSON.parse(val); } catch (_) { continue; }
      if (!parsed || !Array.isArray(parsed._fields)) continue;
      const gaps = missingSchemaFields(cred.category, parsed._fields);
      if (gaps && gaps.missingRequired.length) {
        issues.push({ type: 'incomplete-record', severity: 'medium', name: cred.name,
          message: 'Missing ' + gaps.missingRequired.map(g => g.join(' or ')).join('; ') });
      }
    }
  }

  // Check for credentials with no tags
  for (const cred of index.credentials) {
    if (!cred.tags || cred.tags.length === 0) {
      issues.push({ type: 'no-tags', severity: 'low', name: cred.name,
        message: 'No tags assigned' });
    }
  }

  // Access log analysis — find unused credentials
  let accessLog = [];
  try { accessLog = JSON.parse(fs.readFileSync(ACCESS_LOG_PATH, 'utf8')); } catch (_) {}
  if (accessLog.length > 0) {
    const accessed = new Set(accessLog.map(e => e.name));
    for (const cred of index.credentials) {
      if (!accessed.has(cred.name)) {
        issues.push({ type: 'never-accessed', severity: 'low', name: cred.name,
          message: 'Never accessed since logging started' });
      }
    }
  }

  return {
    total: index.credentials.length,
    issueCount: issues.length,
    issues: issues.sort((a, b) => {
      const sev = { high: 0, medium: 1, low: 2 };
      return (sev[a.severity] || 3) - (sev[b.severity] || 3);
    }),
  };
}

module.exports = {
  get,
  getMetadata,
  getById,
  getByRef,
  set,
  remove,
  rotate,
  list,
  search,
  listProjects,
  renameProject,
  reassignProject,
  removeProject,
  exportEnv,
  stats,
  updateMetadata,
  verifyIntegrity,
  verifyVaultChecksum,
  healStore,
  generateSecret,
  importEnv,
  batchImport,
  history,
  backup,
  ensureRefs,
  merge,
  autoMerge,
  autoMergeAll,
  findMergeSuggestions,
  dismissSuggestion,
  undismissSuggestion,
  listDismissedSuggestions,
  restoreAllDismissedSuggestions,
  splitNameStem,
  fieldLabelForName,
  commonStem,
  TYPE_SCHEMAS,
  schemaForCategory,
  missingSchemaFields,
  detectFieldLabelFromValue,
  orderFieldsBySchema,
  logAccess,
  getAccessLog,
  purgeAccessLog,
  expiring,
  audit,
  loadIndex,
  saveIndex,
  loadVault,
  saveVault,
  createEmptyIndex,
  getDaemonToken,
  daemonTokenPath,
  rotateDaemonToken,
  revokeDaemonToken,
  INDEX_PATH,
  VAULT_PATH,
  VAULT_CHECKSUM_PATH,
  STORE_DIR,
};
