'use strict';

/**
 * classify.test.js
 *
 * Fixtures are deliberately generic (`ACME`, `NORTHWIND`, `CONTOSO`). This file
 * used to assert against the author's real project names, which both leaked a
 * private project inventory into a public repository and encoded one user's
 * setup as the tool's expected behaviour. See the design note at the top of
 * lib/classify.js.
 */

const assert = require('assert');
const { classify, extractProject, suggestPlacement, setUserConfig } = require('../lib/classify');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
  } catch (err) {
    failed++;
    console.error('FAIL: ' + name);
    console.error('  ' + err.message);
  }
}

// Tests must never pick up a developer's real ~/.credmgr/classify.rules.json.
setUserConfig({ aliases: {}, rules: [] });

// ─── classify(): vendor-neutral built-ins ──────────────────────────────────

test('classifies VPS server credentials', () => {
  const r = classify('LINUX_VPS_PASSWORD');
  assert.strictEqual(r.category, 'server');
  assert.strictEqual(r.project, 'global');
  assert.strictEqual(r.sensitivity, 'high');
});

test('classifies wallet private keys as critical', () => {
  const r = classify('MAIN_WALLET_PRIVATE_KEY');
  assert.strictEqual(r.category, 'wallet');
  assert.strictEqual(r.sensitivity, 'critical');
});

test('deployer wallets are critical and no longer bound to a hard-coded project', () => {
  const r = classify('DEPLOYER_PRIVATE_KEY');
  assert.strictEqual(r.category, 'wallet');
  assert.strictEqual(r.sensitivity, 'critical');
  assert.strictEqual(r.project, 'global', 'DEPLOYER is a descriptor, not a project name');
});

test('classifies Cloudflare zone IDs to the embedded project', () => {
  const r = classify('CF_ACME_ZONE_ID');
  assert.strictEqual(r.category, 'cloudflare');
  assert.strictEqual(r.project, 'acme');
});

test('classifies Supabase public keys as low sensitivity', () => {
  const r = classify('NEXT_PUBLIC_SUPABASE_URL');
  assert.strictEqual(r.category, 'supabase');
  assert.strictEqual(r.sensitivity, 'low');
});

test('classifies Supabase service role as high sensitivity', () => {
  const r = classify('SUPABASE_SERVICE_ROLE_KEY');
  assert.strictEqual(r.category, 'supabase');
  assert.strictEqual(r.sensitivity, 'high');
});

test('classifies source-control PATs', () => {
  assert.strictEqual(classify('GITHUB_PAT_CLASSIC').category, 'github');
  assert.strictEqual(classify('GITLAB_TOKEN').category, 'github');
});

test('classifies OpenAI keys', () => {
  const r = classify('OPENAI_API_KEY');
  assert.strictEqual(r.category, 'ai-service');
  assert.ok(r.tags.includes('openai'));
});

test('classifies RPC URLs', () => {
  assert.strictEqual(classify('ALCHEMY_MAINNET_RPC_URL').category, 'rpc');
});

test('classifies cloud provider keys as critical', () => {
  assert.strictEqual(classify('AWS_SECRET_ACCESS_KEY').sensitivity, 'critical');
  assert.strictEqual(classify('AZURE_CLIENT_SECRET').sensitivity, 'critical');
});

test('classifies payment keys as critical', () => {
  assert.strictEqual(classify('STRIPE_SECRET').category, 'payment');
  assert.strictEqual(classify('STRIPE_SECRET').sensitivity, 'critical');
});

test('classifies encryption keys as critical', () => {
  const r = classify('ACME_PII_ENCRYPTION_KEY');
  assert.strictEqual(r.category, 'encryption-key');
  assert.strictEqual(r.sensitivity, 'critical');
});

test('classifies JWT secrets and derives the project generically', () => {
  const r = classify('ACME_JWT_SECRET');
  assert.strictEqual(r.category, 'jwt-secret');
  assert.strictEqual(r.project, 'acme');
});

test('classifies project-scoped admin API keys', () => {
  const r = classify('NORTHWIND_ADMIN_API_KEY');
  assert.strictEqual(r.category, 'api-key');
  assert.strictEqual(r.project, 'northwind');
});

test('classifies VPS credentials with generic project extraction', () => {
  const r = classify('CONTOSO_VPS_PASSWORD');
  assert.strictEqual(r.category, 'server');
  assert.strictEqual(r.project, 'contoso');
});

test('respects overrides', () => {
  const r = classify('UNKNOWN_THING', { project: 'custom-proj', category: 'custom' });
  assert.strictEqual(r.project, 'custom-proj');
  assert.strictEqual(r.category, 'custom');
});

test('defaults to global/api-key for unknown names', () => {
  const r = classify('ZZZ');
  assert.strictEqual(r.project, 'global');
  assert.strictEqual(r.category, 'api-key');
  assert.strictEqual(r.sensitivity, 'medium');
});

// ─── user configuration ────────────────────────────────────────────────────

test('user aliases normalise project names', () => {
  setUserConfig({ aliases: { acme_corp: 'acme', 'acme-corp': 'acme' }, rules: [] });
  assert.strictEqual(extractProject('ACME_CORP_API_KEY'), 'acme');
  setUserConfig({ aliases: {}, rules: [] });
});

test('user rules are evaluated before the built-ins', () => {
  setUserConfig({
    aliases: {},
    rules: [{ pattern: /^ACME_/i, category: 'custom-cat', project: 'acme', tags: ['x'], sensitivity: 'critical' }],
  });
  const r = classify('ACME_API_KEY');
  assert.strictEqual(r.category, 'custom-cat', 'user rule must win over the built-in _API_KEY rule');
  assert.strictEqual(r.sensitivity, 'critical');
  setUserConfig({ aliases: {}, rules: [] });
});

test('a malformed user config never breaks classification', () => {
  setUserConfig({ aliases: null, rules: 'not-an-array' });
  const r = classify('ACME_API_KEY');
  assert.strictEqual(r.category, 'api-key');
  setUserConfig({ aliases: {}, rules: [] });
});

// ─── extractProject() ──────────────────────────────────────────────────────

test('extractProject: derives the project from the first segment', () => {
  assert.strictEqual(extractProject('ACME_VPS_PASSWORD'), 'acme');
  assert.strictEqual(extractProject('NORTHWIND_ADMIN_KEY'), 'northwind');
});

test('extractProject: returns null for descriptor prefixes', () => {
  assert.strictEqual(extractProject('MAIN_WALLET_KEY'), null);
  assert.strictEqual(extractProject('TEST_THING'), null);
  assert.strictEqual(extractProject('GLOBAL_THING'), null);
});

test('extractProject: returns null for a too-short first segment', () => {
  assert.strictEqual(extractProject('X_THING'), null);
});

// ─── suggestPlacement() ────────────────────────────────────────────────────

test('suggestPlacement: uses classification for known VPS patterns', () => {
  const r = suggestPlacement('ACME_VPS_NEW_THING', []);
  assert.strictEqual(r.project, 'acme');
});

test('suggestPlacement: falls back to global for unmatched patterns', () => {
  const r = suggestPlacement('ZZ', []);
  assert.strictEqual(r.project, 'global');
});

test('suggestPlacement: finds similar credentials when score >= 2', () => {
  const existing = [
    { name: 'MYPROJECT_API_KEY', project: 'myproject', tags: ['api', 'myproject'], category: 'api-key' },
    { name: 'MYPROJECT_DB_PASS', project: 'myproject', tags: ['database', 'myproject'], category: 'database' },
  ];
  const r = suggestPlacement('MYPROJECT_SECRET_API', existing);
  assert.strictEqual(r.project, 'myproject');
});

// ─── no personal data in this repository ───────────────────────────────────

test('the classifier ships no specific project as a built-in rule', () => {
  const { BUILTIN_RULES } = require('../lib/classify');
  // A public tool must not ship one user's project inventory. This is asserted
  // STRUCTURALLY rather than as a denylist of names — a denylist would itself
  // have to spell out the private names it exists to keep out.
  const allowed = new Set(['global', '$prefix', '$1', '$extract_cf']);
  const leaked = BUILTIN_RULES
    .map(r => r.project)
    .filter(p => !allowed.has(p));
  assert.deepStrictEqual(leaked, [],
    'every built-in rule must resolve its project generically ($prefix/$1/$extract_cf) or to ' +
    '"global". A concrete project name here is somebody\'s private inventory — put it in ' +
    '<vault>/.credmgr/classify.rules.json instead.');
});

// ─── Summary ───────────────────────────────────────────────────────────────

console.log('\nclassify.test.js: ' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exit(1);
