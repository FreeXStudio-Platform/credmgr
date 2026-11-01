'use strict';

/**
 * Auto-classify credentials by name pattern into project + category.
 *
 * Rules are ordered: first match wins. User rules are evaluated BEFORE the
 * built-ins, so anything you define always takes precedence.
 *
 * Returns { project, category, tags[], sensitivity }.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * DESIGN NOTE — why there are no project names in this file
 *
 * Earlier versions hard-coded one user's private project names (their clients,
 * their infrastructure) directly into these rules. That was wrong twice over:
 * it leaked the author's project inventory to anyone reading the source, and it
 * made a general-purpose tool useless to everyone else.
 *
 * The built-in rules below now cover only **vendor-neutral, universally true**
 * shapes: `_PRIVATE_KEY` is a wallet key for everybody; `SUPABASE_` is Supabase
 * for everybody. Anything specific to *your* projects belongs in your own
 * config file, which is never part of this repository:
 *
 *     <vault home>/.credmgr/classify.rules.json   (see lib/paths.js)
 *
 *     {
 *       "aliases": { "acme_corp": "acme", "acme-corp": "acme" },
 *       "rules": [
 *         { "pattern": "^ACME_", "flags": "i", "category": "api-key",
 *           "project": "acme", "tags": ["acme"], "sensitivity": "high" }
 *       ]
 *     }
 *
 * When no rule names a project, the project is derived generically from the
 * name's first segment: `ACME_API_KEY` → `acme`. That works for every user with
 * zero configuration.
 * ─────────────────────────────────────────────────────────────────────────────
 */

const fs = require('fs');
const path = require('path');

// ── Built-in rules — vendor-neutral only. No user's project may be added here.
const BUILTIN_RULES = [
  // Server / VPS
  { pattern: /^LINUX_VPS_/i,            category: 'server',         project: 'global',    tags: ['vps', 'linux'],                  sensitivity: 'high' },
  { pattern: /^WINDOWS_VPS_/i,          category: 'server',         project: 'global',    tags: ['vps', 'windows'],                sensitivity: 'high' },
  { pattern: /^LOCAL_SUDO_/i,           category: 'server',         project: 'global',    tags: ['local', 'sudo'],                 sensitivity: 'high' },
  { pattern: /^(.+?)_VPS_/i,            category: 'server',         project: '$1',        tags: ['vps', 'deploy'],                 sensitivity: 'high' },
  { pattern: /_SSH_KEY$/i,              category: 'ssh-key',        project: '$prefix',   tags: ['ssh'],                           sensitivity: 'high' },

  // Wallets — the most sensitive class in the vault
  { pattern: /^MAIN_WALLET_/i,          category: 'wallet',         project: 'global',    tags: ['wallet', 'personal', 'mainnet'], sensitivity: 'critical' },
  { pattern: /^DEPLOYER_/i,             category: 'wallet',         project: '$prefix',   tags: ['wallet', 'deployer'],            sensitivity: 'critical' },
  { pattern: /^TESTNET_WALLET_/i,       category: 'wallet',         project: '$prefix',   tags: ['wallet', 'testnet'],             sensitivity: 'high' },
  { pattern: /_PRIVATE_KEY$/i,          category: 'wallet',         project: '$prefix',   tags: ['wallet', 'private-key'],         sensitivity: 'critical' },
  { pattern: /_WALLET_/i,               category: 'wallet',         project: '$prefix',   tags: ['wallet'],                        sensitivity: 'critical' },
  { pattern: /_MNEMONIC$/i,             category: 'wallet',         project: '$prefix',   tags: ['wallet', 'mnemonic'],            sensitivity: 'critical' },
  { pattern: /_RECOVERY_PHRASE$/i,      category: 'wallet',         project: '$prefix',   tags: ['wallet', 'recovery'],            sensitivity: 'critical' },
  { pattern: /_SEED_PHRASE$/i,          category: 'wallet',         project: '$prefix',   tags: ['wallet', 'seed'],                sensitivity: 'critical' },

  // Blockchain / RPC
  { pattern: /_RPC_URL$/i,              category: 'rpc',            project: 'global',    tags: ['rpc', 'blockchain'],             sensitivity: 'low' },
  { pattern: /^ALCHEMY_/i,              category: 'rpc',            project: 'global',    tags: ['rpc', 'alchemy'],                sensitivity: 'medium' },
  { pattern: /^INFURA_/i,               category: 'rpc',            project: 'global',    tags: ['rpc', 'infura'],                 sensitivity: 'medium' },
  { pattern: /^QUICKNODE_/i,            category: 'rpc',            project: 'global',    tags: ['rpc', 'quicknode'],              sensitivity: 'medium' },

  // Backend / platform vendors
  { pattern: /^NEXT_PUBLIC_SUPABASE_/i, category: 'supabase',       project: 'global',    tags: ['supabase', 'public'],            sensitivity: 'low' },
  { pattern: /^SUPABASE_/i,             category: 'supabase',       project: 'global',    tags: ['supabase'],                      sensitivity: 'high' },
  { pattern: /^FIREBASE_/i,             category: 'api-key',        project: 'global',    tags: ['firebase'],                      sensitivity: 'high' },
  { pattern: /^VERCEL_/i,               category: 'integration',    project: 'global',    tags: ['vercel', 'deploy'],              sensitivity: 'high' },
  { pattern: /^NETLIFY_/i,              category: 'integration',    project: 'global',    tags: ['netlify', 'deploy'],             sensitivity: 'high' },
  { pattern: /^AWS_/i,                  category: 'cloud',          project: 'global',    tags: ['aws'],                           sensitivity: 'critical' },
  { pattern: /^GCP_|^GOOGLE_CLOUD_/i,   category: 'cloud',          project: 'global',    tags: ['gcp'],                           sensitivity: 'critical' },
  { pattern: /^AZURE_/i,                category: 'cloud',          project: 'global',    tags: ['azure'],                         sensitivity: 'critical' },

  // Cloudflare
  { pattern: /^CF_.*_ZONE_ID$/i,        category: 'cloudflare',     project: '$extract_cf', tags: ['cloudflare', 'zone'],          sensitivity: 'medium' },
  { pattern: /^CF_|^CLOUDFLARE_/i,      category: 'cloudflare',     project: 'global',    tags: ['cloudflare'],                    sensitivity: 'high' },

  // Source control
  { pattern: /^GITHUB_|^GITLAB_|^BITBUCKET_/i, category: 'github',  project: 'global',    tags: ['scm', 'pat'],                    sensitivity: 'high' },

  // Database
  { pattern: /_POSTGRES_/i,             category: 'database',       project: '$prefix',   tags: ['database', 'postgres'],          sensitivity: 'high' },
  { pattern: /_MYSQL_|_MARIADB_/i,      category: 'database',       project: '$prefix',   tags: ['database', 'mysql'],             sensitivity: 'high' },
  { pattern: /_MONGO(DB)?_/i,           category: 'database',       project: '$prefix',   tags: ['database', 'mongodb'],           sensitivity: 'high' },
  { pattern: /_REDIS_/i,                category: 'database',       project: '$prefix',   tags: ['database', 'redis'],             sensitivity: 'high' },
  { pattern: /_DB_/i,                   category: 'database',       project: '$prefix',   tags: ['database'],                      sensitivity: 'high' },

  // Crypto material
  { pattern: /_ENCRYPTION_KEY$/i,       category: 'encryption-key', project: '$prefix',   tags: ['encryption'],                    sensitivity: 'critical' },
  { pattern: /_JWT_SECRET$/i,           category: 'jwt-secret',     project: '$prefix',   tags: ['jwt', 'auth'],                   sensitivity: 'high' },
  { pattern: /_SECRET_KEY$/i,           category: 'jwt-secret',     project: '$prefix',   tags: ['secret'],                        sensitivity: 'high' },
  { pattern: /_SESSION_SECRET$/i,       category: 'jwt-secret',     project: '$prefix',   tags: ['session', 'auth'],               sensitivity: 'high' },

  // OAuth
  { pattern: /_CLIENT_ID$/i,            category: 'oauth',          project: '$prefix',   tags: ['oauth'],                         sensitivity: 'medium' },
  { pattern: /_CLIENT_SECRET$/i,        category: 'oauth',          project: '$prefix',   tags: ['oauth'],                         sensitivity: 'high' },

  // AI services
  { pattern: /^OPENAI_/i,               category: 'ai-service',     project: 'global',    tags: ['openai', 'ai'],                  sensitivity: 'high' },
  { pattern: /^ANTHROPIC_/i,            category: 'ai-service',     project: 'global',    tags: ['anthropic', 'ai'],               sensitivity: 'high' },
  { pattern: /^ELEVENLABS_/i,           category: 'ai-service',     project: 'global',    tags: ['elevenlabs', 'ai'],              sensitivity: 'high' },
  { pattern: /^HUGGINGFACE_|^HF_/i,     category: 'ai-service',     project: 'global',    tags: ['huggingface', 'ai'],             sensitivity: 'high' },

  // Media / CDN / analytics / comms
  { pattern: /^CLOUDINARY_/i,           category: 'cdn',            project: 'global',    tags: ['cloudinary', 'cdn'],             sensitivity: 'medium' },
  { pattern: /^POSTHOG_|^MIXPANEL_|^SENTRY_/i, category: 'analytics', project: 'global',  tags: ['analytics'],                     sensitivity: 'medium' },
  { pattern: /^RESEND_|^SENDGRID_|^MAILGUN_|^POSTMARK_|^SMTP_/i, category: 'email', project: 'global', tags: ['email'],            sensitivity: 'high' },
  { pattern: /^TWILIO_|^SLACK_|^DISCORD_|^TELEGRAM_/i, category: 'integration', project: 'global', tags: ['messaging'],            sensitivity: 'high' },
  { pattern: /^STRIPE_|^PADDLE_|^LEMONSQUEEZY_/i, category: 'payment', project: 'global', tags: ['payment'],                       sensitivity: 'critical' },

  // Web3 tooling
  { pattern: /^WALLETCONNECT_|^REOWN_/i, category: 'integration',   project: 'global',    tags: ['web3'],                          sensitivity: 'low' },
  { pattern: /^ETHERSCAN_|^BLOCKSCOUT_|^COVALENT_/i, category: 'api-key', project: 'global', tags: ['explorer'],                   sensitivity: 'medium' },

  // Generic API keys — project comes from the prefix
  { pattern: /^(.+?)_ADMIN_API_KEY$/i,  category: 'api-key',        project: '$1',        tags: ['admin', 'api-key'],              sensitivity: 'high' },
  { pattern: /^(.+?)_INGEST_API_KEY$/i, category: 'api-key',        project: '$1',        tags: ['ingest', 'api-key'],             sensitivity: 'high' },
  { pattern: /_API_KEY$/i,              category: 'api-key',        project: '$prefix',   tags: ['api-key'],                       sensitivity: 'high' },
  { pattern: /_API_SECRET$/i,           category: 'api-key',        project: '$prefix',   tags: ['api-key'],                       sensitivity: 'high' },
  { pattern: /_API_TOKEN$/i,            category: 'api-key',        project: '$prefix',   tags: ['api-key', 'token'],              sensitivity: 'high' },
  { pattern: /_ACCESS_TOKEN$/i,         category: 'api-key',        project: '$prefix',   tags: ['token'],                         sensitivity: 'high' },
  { pattern: /_REFRESH_TOKEN$/i,        category: 'api-key',        project: '$prefix',   tags: ['token', 'refresh'],              sensitivity: 'high' },

  // Web admin logins
  { pattern: /^(.+?)_WEB_ADMIN/i,       category: 'web-admin',      project: '$1',        tags: ['web', 'admin'],                  sensitivity: 'high' },
  { pattern: /_PASSWORD$/i,             category: 'web-admin',      project: '$prefix',   tags: ['password'],                      sensitivity: 'high' },
];

// First name segments that are never a project — they are descriptors.
const NON_PROJECT_PREFIXES = new Set([
  'main', 'local', 'linux', 'windows', 'macos', 'next', 'testnet', 'mainnet',
  'deployer', 'my', 'the', 'new', 'old', 'temp', 'tmp', 'test', 'dev', 'prod',
  'staging', 'default', 'global', 'shared', 'common', 'personal',
]);

const MAX_USER_PATTERN_LEN = 200;   // bound user-supplied regex (ReDoS hygiene)
const MAX_USER_RULES = 500;

let _user = null;   // { aliases: {}, rules: [] } — lazily loaded, cacheable

function userConfigPath(opts) {
  if (opts && opts.classifyRulesPath) return opts.classifyRulesPath;
  const home = require('./paths').vaultHome();
  return path.join(home, '.credmgr', 'classify.rules.json');
}

/**
 * Load user rules. Malformed config is a warning, never a crash: a broken rules
 * file must not stop you reaching your credentials.
 */
function loadUserConfig(opts) {
  if (_user && !(opts && opts.reload)) return _user;
  const out = { aliases: {}, rules: [] };
  try {
    const p = userConfigPath(opts);
    if (fs.existsSync(p)) {
      const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
      if (raw && typeof raw.aliases === 'object' && raw.aliases) {
        for (const [k, v] of Object.entries(raw.aliases)) {
          if (typeof k === 'string' && typeof v === 'string') out.aliases[k.toLowerCase()] = v;
        }
      }
      if (Array.isArray(raw.rules)) {
        for (const r of raw.rules.slice(0, MAX_USER_RULES)) {
          if (!r || typeof r.pattern !== 'string') continue;
          if (r.pattern.length > MAX_USER_PATTERN_LEN) continue;
          let re;
          try { re = new RegExp(r.pattern, typeof r.flags === 'string' ? r.flags : 'i'); }
          catch (_) { continue; }               // invalid regex → skip that rule
          out.rules.push({
            pattern: re,
            category: typeof r.category === 'string' ? r.category : 'api-key',
            project: typeof r.project === 'string' ? r.project : '$prefix',
            tags: Array.isArray(r.tags) ? r.tags.filter(t => typeof t === 'string') : [],
            sensitivity: ['low', 'medium', 'high', 'critical'].includes(r.sensitivity) ? r.sensitivity : 'medium',
          });
        }
      }
    }
  } catch (_) { /* unreadable/malformed → fall back to built-ins only */ }
  _user = out;
  return out;
}

/**
 * Test/CLI hook: inject config without touching disk. Pass null to reset.
 *
 * This normalises exactly like loadUserConfig(). An earlier version stored
 * whatever it was handed, so `setUserConfig({rules:'oops'})` corrupted the
 * module for the rest of the process — a bad config must degrade to "no user
 * rules", never to a broken classifier.
 */
function setUserConfig(cfg) {
  if (!cfg) { _user = null; return; }
  const aliases = {};
  if (cfg.aliases && typeof cfg.aliases === 'object' && !Array.isArray(cfg.aliases)) {
    for (const [k, v] of Object.entries(cfg.aliases)) {
      if (typeof k === 'string' && typeof v === 'string') aliases[k.toLowerCase()] = v;
    }
  }
  const rules = [];
  if (Array.isArray(cfg.rules)) {
    for (const r of cfg.rules.slice(0, MAX_USER_RULES)) {
      if (!r || (typeof r.pattern !== 'string' && !(r.pattern instanceof RegExp))) continue;
      let re = r.pattern;
      if (typeof re === 'string') {
        if (re.length > MAX_USER_PATTERN_LEN) continue;
        try { re = new RegExp(re, typeof r.flags === 'string' ? r.flags : 'i'); } catch (_) { continue; }
      }
      rules.push({
        pattern: re,
        category: typeof r.category === 'string' ? r.category : 'api-key',
        project: typeof r.project === 'string' ? r.project : '$prefix',
        tags: Array.isArray(r.tags) ? r.tags.filter(t => typeof t === 'string') : [],
        sensitivity: ['low', 'medium', 'high', 'critical'].includes(r.sensitivity) ? r.sensitivity : 'medium',
      });
    }
  }
  _user = { aliases, rules };
}

/**
 * Derive a project from a credential name.
 *   ACME_API_KEY        → "acme"
 *   MAIN_WALLET_KEY     → null  (descriptor, not a project)
 * User aliases are consulted first, so `ACME_CORP_` can normalise to `acme`.
 */
function extractProject(name, opts) {
  const lower = String(name).toLowerCase();
  const { aliases } = loadUserConfig(opts);

  for (const [alias, project] of Object.entries(aliases)) {
    const a = alias.replace(/-/g, '_');
    if (lower.startsWith(alias + '_') || lower.startsWith(a + '_')) return project;
  }
  const first = lower.split('_')[0];
  if (aliases[first]) return aliases[first];
  if (!first || first.length < 2 || NON_PROJECT_PREFIXES.has(first)) return null;
  return first;
}

/** CF_ACME_ZONE_ID → "acme" */
function extractCfProject(name, opts) {
  const m = String(name).match(/^CF_(.+?)_ZONE_ID$/i);
  if (!m) return 'global';
  const sub = m[1].toLowerCase();
  const { aliases } = loadUserConfig(opts);
  return aliases[sub] || sub;
}

/**
 * Classify a credential by name.
 * @param {string} name       e.g. "ACME_VPS_PASSWORD"
 * @param {object} [overrides] { project, category, tags, sensitivity }
 * @param {object} [opts]      { classifyRulesPath, reload }
 */
function classify(name, overrides, opts) {
  const result = { project: 'global', category: 'api-key', tags: [], sensitivity: 'medium' };
  const { aliases, rules: userRules } = loadUserConfig(opts);

  // User rules first — yours always win over the built-ins.
  const all = [...(Array.isArray(userRules) ? userRules : []), ...BUILTIN_RULES];
  for (const rule of all) {
    // Defence in depth: a malformed rule is skipped, never thrown on. Reaching
    // your credentials must not depend on a config file being well-formed.
    if (!rule || !(rule.pattern instanceof RegExp)) continue;
    const match = String(name).match(rule.pattern);
    if (!match) continue;

    result.category = typeof rule.category === 'string' ? rule.category : 'api-key';
    result.tags = Array.isArray(rule.tags) ? [...rule.tags] : [];
    result.sensitivity = rule.sensitivity || 'medium';

    if (rule.project === '$prefix') {
      result.project = extractProject(name, opts) || 'global';
    } else if (rule.project === '$1' && match[1]) {
      const normalized = match[1].toLowerCase().replace(/_/g, '-');
      result.project = aliases[normalized] || aliases[match[1].toLowerCase()] || normalized;
    } else if (rule.project === '$extract_cf') {
      result.project = extractCfProject(name, opts);
    } else {
      result.project = rule.project;
    }
    break;
  }

  if (overrides) {
    if (overrides.project) result.project = overrides.project;
    if (overrides.category) result.category = overrides.category;
    if (overrides.tags) result.tags = [...new Set([...result.tags, ...overrides.tags])];
    if (overrides.sensitivity) result.sensitivity = overrides.sensitivity;
  }
  return result;
}

/**
 * Suggest where a credential fits among the ones you already have.
 * Falls back to name-similarity against the existing store when the rules
 * cannot place it.
 */
function suggestPlacement(name, existingCredentials, opts) {
  const classification = classify(name, undefined, opts);
  if (classification.project !== 'global') return classification;

  const parts = String(name).toLowerCase().split('_').filter(p => p.length > 2);
  let bestMatch = null;
  let bestScore = 0;

  for (const cred of existingCredentials || []) {
    const credParts = String(cred.name).toLowerCase().split('_').filter(p => p.length > 2);
    let score = 0;
    for (const part of parts) {
      if (credParts.includes(part)) score += 1;
      if (cred.tags && cred.tags.some(t => String(t).includes(part))) score += 0.5;
    }
    if (score > bestScore) { bestScore = score; bestMatch = cred; }
  }

  if (bestMatch && bestScore >= 2) {
    return {
      ...classification,
      project: bestMatch.project,
      tags: [...new Set([...classification.tags, ...(bestMatch.tags || [])])],
    };
  }
  return classification;
}

module.exports = {
  classify,
  suggestPlacement,
  extractProject,
  loadUserConfig,
  setUserConfig,
  userConfigPath,
  RULES: BUILTIN_RULES,
  BUILTIN_RULES,
  NON_PROJECT_PREFIXES,
};
