'use strict';

// Machine-binding for the vault's age identity (master.key): once enabled, a
// copied vault.age + index.json + master.key cannot be decrypted on any
// machine other than the one that enabled it — even by running `age -d`
// directly, bypassing credmgr's own code entirely.
//
// HOW: master.key on disk stops being the raw age identity once locked — it
// becomes that identity encrypted (AES-256-GCM) under a key derived (scrypt)
// from THIS machine's hardware/OS identity plus a per-install salt stored
// alongside it. The salt is not a secret by itself — it's useless without a
// matching machine fingerprint, and that fingerprint lives OUTSIDE the
// credmgr directory tree (/etc/machine-id, IOPlatformUUID, a registry key),
// so it can't be exfiltrated by copying the vault directory (or wherever this
// install lives) to another machine. lib/crypto.js's decrypt()/
// decryptToBuffer() transparently unwrap the identity into a short-lived
// temp file immediately before invoking `age`, and remove it immediately
// after — the plaintext identity never persists on disk under this name.
//
// Cross-platform fingerprint sources (deliberately NOT copied along with the
// vault directory — that is the whole point):
//   macOS   — IOPlatformUUID (via `ioreg`), a hardware-derived UUID
//   Linux   — /etc/machine-id (systemd), falling back to /var/lib/dbus/machine-id
//   Windows — HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid (best-effort)
//   other   — hostname+platform+arch (weakest tier — documented, not hidden:
//             this only stops a casual directory copy, not an attacker who
//             can also clone the source machine's exact OS install)
//
// Deliberately has ZERO dependency on lib/crypto.js (no `require('./crypto')`)
// to avoid a require cycle — crypto.js calls INTO this module, not the other
// way around. Every function that needs the vault's identity path takes it
// as a parameter; every function that needs the machine fingerprint accepts
// an optional `opts.fingerprintOverride` so tests can simulate "a different
// machine" deterministically — there is no env-var or config-file override,
// so this can never be spoofed by anything that can merely copy the vault
// directory (the actual threat this feature defends against).

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const CREDMGR_DIR = path.join(require('./paths').vaultHome(), '.credmgr');
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };
const WRAP_MARKER = 'credmgr-machine-locked-v1';

// ─── Config (shares .credmgr/config.json with crypto.js / lib/lock.js) ─────

function configPath(opts) {
  return (opts && opts.configPath) || path.join(CREDMGR_DIR, 'config.json');
}
function readConfig(opts) {
  try { return JSON.parse(fs.readFileSync(configPath(opts), 'utf8')); } catch (_) { return {}; }
}
function writeConfig(cfg, opts) {
  const p = configPath(opts);
  const dir = path.dirname(p);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(p, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
}

// ─── Fingerprint ────────────────────────────────────────────────────────────

function detectFingerprint() {
  const platform = os.platform();
  try {
    if (platform === 'darwin') {
      const out = execFileSync('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], { encoding: 'utf8' });
      const m = out.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
      if (m) return 'darwin:' + m[1];
    } else if (platform === 'linux') {
      for (const p of ['/etc/machine-id', '/var/lib/dbus/machine-id']) {
        if (fs.existsSync(p)) {
          const id = fs.readFileSync(p, 'utf8').trim();
          if (id) return 'linux:' + id;
        }
      }
    } else if (platform === 'win32') {
      const out = execFileSync(
        'reg', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'],
        { encoding: 'utf8' }
      );
      const m = out.match(/MachineGuid\s+REG_SZ\s+(\S+)/);
      if (m) return 'win32:' + m[1];
    }
  } catch (_) { /* fall through to the generic fallback below */ }
  return 'generic:' + os.hostname() + ':' + platform + ':' + os.arch();
}

function getFingerprint(opts) {
  return (opts && opts.fingerprintOverride) || detectFingerprint();
}

function deriveWrapKey(fingerprint, saltHex) {
  return crypto.scryptSync(fingerprint, Buffer.from(saltHex, 'hex'), SCRYPT.keylen, {
    N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p,
  });
}

// ─── Wrap / unwrap (AES-256-GCM) ────────────────────────────────────────────

function wrapIdentity(plaintext, fingerprint) {
  const salt = crypto.randomBytes(16).toString('hex');
  const key = deriveWrapKey(fingerprint, salt);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    marker: WRAP_MARKER,
    salt,
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    ciphertext: ciphertext.toString('hex'),
  };
}

function unwrapIdentity(wrapped, fingerprint) {
  if (!wrapped || wrapped.marker !== WRAP_MARKER) {
    throw new Error('Not a machine-locked identity (missing/bad marker)');
  }
  const key = deriveWrapKey(fingerprint, wrapped.salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(wrapped.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(wrapped.tag, 'hex'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(wrapped.ciphertext, 'hex')),
    decipher.final(),
  ]);
  return plaintext.toString('utf8');
}

function readWrappedFile(identityPath) {
  const raw = fs.readFileSync(identityPath, 'utf8');
  let parsed;
  try { parsed = JSON.parse(raw); } catch (_) {
    throw new Error('Identity file is not machine-locked (not JSON)');
  }
  return parsed;
}

// ─── Enable / disable (mutate the identity file on disk) ───────────────────

function isEnabled(opts) {
  const cfg = readConfig(opts);
  return !!(cfg.machineLock && cfg.machineLock.enabled);
}

/**
 * Lock `identityPath` (the vault's age identity file) to the current
 * machine. Atomic and self-verifying: writes the wrapped form to a sibling
 * temp file, confirms it unwraps back to byte-identical plaintext, and ONLY
 * THEN renames it over the real file — if anything fails, the original
 * plaintext identity is left completely untouched.
 */
function enable(identityPath, opts) {
  if (isEnabled(opts)) throw new Error('Machine lock is already enabled');
  const plaintext = fs.readFileSync(identityPath, 'utf8');
  if (!/AGE-SECRET-KEY-/.test(plaintext)) {
    throw new Error('Identity file does not look like a plaintext age key — refusing to wrap');
  }
  const fingerprint = getFingerprint(opts);
  const wrapped = wrapIdentity(plaintext, fingerprint);

  const tmp = identityPath + '.tmp-lock';
  fs.writeFileSync(tmp, JSON.stringify(wrapped), { mode: 0o600 });
  const check = unwrapIdentity(readWrappedFile(tmp), fingerprint);
  if (check !== plaintext) {
    fs.unlinkSync(tmp);
    throw new Error('Machine-lock self-check failed — identity file left unchanged');
  }
  fs.renameSync(tmp, identityPath);

  const cfg = readConfig(opts);
  cfg.machineLock = {
    enabled: true,
    fingerprintHash: crypto.createHash('sha256').update(fingerprint).digest('hex'),
    enabledAt: new Date().toISOString(),
  };
  writeConfig(cfg, opts);
}

/**
 * Reverse enable() — only succeeds on the SAME machine that locked it, since
 * unwrapping requires deriving the same key from the current fingerprint.
 * That is the correct, self-consistent invariant: this can only ever be
 * turned off from the one place it is safe to turn off.
 */
function disable(identityPath, opts) {
  if (!isEnabled(opts)) throw new Error('Machine lock is not enabled');
  const fingerprint = getFingerprint(opts);
  const plaintext = unwrapIdentity(readWrappedFile(identityPath), fingerprint);

  const tmp = identityPath + '.tmp-unlock';
  fs.writeFileSync(tmp, plaintext, { mode: 0o600 });
  fs.renameSync(tmp, identityPath);

  const cfg = readConfig(opts);
  delete cfg.machineLock;
  writeConfig(cfg, opts);
}

// ─── The actual hook lib/crypto.js calls before every age invocation ───────

function tempBaseDir() {
  // Best-effort RAM-backed location on Linux — the unwrapped identity is
  // never written to physical storage there. macOS has no tmpfs-backed /tmp
  // by default, so os.tmpdir() (disk) is the practical floor on that
  // platform; the file is 0600, single-use, and removed immediately after.
  if (os.platform() === 'linux') {
    try { fs.accessSync('/dev/shm', fs.constants.W_OK); return '/dev/shm'; } catch (_) { /* fall through */ }
  }
  return os.tmpdir();
}

/**
 * Resolves the identity PATH `age` should actually be invoked with:
 *   - not locked  → identityPath unchanged, cleanup() is a no-op
 *   - locked      → a freshly-written, single-use temp file holding the
 *                    unwrapped plaintext identity; caller MUST call
 *                    cleanup() once `age` has run, in a finally block
 * Throws a clear, non-leaky error if this machine's fingerprint doesn't
 * unwrap the identity (wrong machine, or this one's hardware/OS identity
 * changed) — this is the actual enforcement point of the whole feature.
 */
function resolveIdentity(identityPath, opts) {
  if (!isEnabled(opts)) return { path: identityPath, cleanup: () => {} };
  const fingerprint = getFingerprint(opts);
  let plaintext;
  try {
    plaintext = unwrapIdentity(readWrappedFile(identityPath), fingerprint);
  } catch (_) {
    throw new Error(
      'This vault is machine-locked and will not decrypt here — it was locked to a ' +
      'different machine, or this machine\'s hardware/OS identity changed.'
    );
  }
  const dir = fs.mkdtempSync(path.join(tempBaseDir(), 'credmgr-lock-'));
  const file = path.join(dir, 'identity');
  fs.writeFileSync(file, plaintext, { mode: 0o600 });
  return {
    path: file,
    cleanup: () => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) { /* best-effort */ } },
  };
}

function status(opts) {
  const cfg = readConfig(opts);
  return {
    enabled: isEnabled(opts),
    enabledAt: (cfg.machineLock && cfg.machineLock.enabledAt) || null,
    platform: os.platform(),
  };
}

module.exports = {
  detectFingerprint,
  getFingerprint,
  wrapIdentity,
  unwrapIdentity,
  isEnabled,
  enable,
  disable,
  resolveIdentity,
  status,
};
