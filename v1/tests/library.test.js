'use strict';

const assert = require('assert');
const credmgr = require('..');
let passed = 0;
let failed = 0;

async function test(name, fn) {
  try { await fn(); passed++; }
  catch (err) { failed++; console.error('FAIL: ' + name + '\n  ' + err.message); }
}

async function run() {
  const project = '_library_env_test';
  const names = ['_LIB_ENV_A', '_LIB_ENV_EMPTY', '__proto__'];
  try {
    credmgr.set(names[0], 'synthetic-library-value', { project });
    credmgr.set(names[1], '', { project });
    credmgr.set(names[2], 'synthetic-prototype-name', { project });
    await test('getEnvObject returns plaintext strings suitable for a child-process environment', async () => {
      const result = await credmgr.getEnvObject({ project });
      assert.ok(result[names[0]] === 'synthetic-library-value', 'environment values must be plaintext strings');
      assert.strictEqual(result[names[1]], '', 'empty credential remains an empty string');
      assert.ok(Object.values(result).every(v => typeof v === 'string'));
    });
    await test('getEnvObject preserves special names as own environment keys', async () => {
      const result = await credmgr.getEnvObject({ project });
      assert.ok(Object.prototype.hasOwnProperty.call(result, '__proto__'));
      assert.ok(result.__proto__ === 'synthetic-prototype-name');
      assert.strictEqual(Object.getPrototypeOf(result), Object.prototype);
    });
  } finally { for (const name of names) credmgr.remove(name); }
  console.log('library.test.js: ' + passed + ' passed, ' + failed + ' failed');
  if (failed) process.exit(1);
}
run();
