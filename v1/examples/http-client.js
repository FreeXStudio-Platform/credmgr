'use strict';

/**
 * Example: Mode 2 — credmgr daemon + HTTP client
 *
 * Prereq:  In another terminal, run:  credmgr daemon
 *          (or `credmgr dashboard` which also exposes the same API)
 *
 * Run:     node examples/http-client.js
 */

const { Client, CredmgrError } = require('../client');

async function main() {
  const cm = new Client({
    host: '127.0.0.1',
    port: 9876,
    token: process.env.CREDMGR_TOKEN || null,
    source: 'example:http-client',
  });

  // 1) Probe the daemon
  const health = await cm.health();
  console.log('Daemon health:', health);

  // 2) Search — same API as the library mode
  const matches = await cm.search('api');
  console.log('\nMatches for "api":', matches.slice(0, 5).map((m) => m.name));

  // 3) Read one
  if (matches[0]) {
    try {
      const value = await cm.get(matches[0].name);
      console.log('\nRead', matches[0].name, '— value length', value.length);
    } catch (err) {
      if (err instanceof CredmgrError) {
        console.error('Read failed:', err.status, err.message);
      } else {
        throw err;
      }
    }
  }

  // 4) Bulk env bag for a project
  const env = await cm.getEnvObject({ project: 'acme' });
  console.log('\nacme env bag has', Object.keys(env).length, 'entries');

  // 5) Demo error handling: ask for a missing credential
  try {
    await cm.get('DEFINITELY_NOT_A_REAL_CREDENTIAL_12345');
  } catch (err) {
    console.log('\nExpected error for missing cred:', err.status, err.message);
  }
}

main().catch((err) => {
  console.error('Example failed:', err.message);
  if (err.code === 'ECONNREFUSED') {
    console.error('→ The daemon is not running. Start it with:  credmgr daemon');
  }
  process.exit(1);
});
