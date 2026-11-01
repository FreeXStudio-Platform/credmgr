'use strict';

/**
 * Example: Mode 3 — credmgr as a Node.js library
 *
 * Run:  node examples/node-library.js
 *
 * This example is run in-place (it imports '..' rather than 'credmgr')
 * so you can exercise the library without publishing it to npm.
 */

const credmgr = require('..');

async function main() {
  console.log('credmgr library example\n');

  // 1) Metadata-only list (no decryption)
  const projects = credmgr.listProjects();
  console.log('Projects:', projects.map((p) => p.id).join(', '));

  // 2) Search — metadata only, safe to print
  const matches = credmgr.search('api');
  console.log('\nMatches for "api":');
  for (const m of matches.slice(0, 5)) {
    console.log('  #' + String(m.ref).padStart(4, '0') + '  ' + m.name);
  }

  // 3) Read a specific credential (will create an audit log entry)
  const firstName = matches[0] && matches[0].name;
  if (firstName) {
    console.log('\nReading: ' + firstName);
    const value = await credmgr.get(firstName, { source: 'example:node-library' });
    console.log('  value length:', value.length, 'chars');
    // NEVER log the value itself — just prove we got it.
  }

  // 4) Load every credential for a project into env-var shape
  const projectEnv = await credmgr.getEnvObject(
    { project: 'acme' },
    { source: 'example:node-library' }
  );
  console.log('\nacme env bag has', Object.keys(projectEnv).length, 'entries');

  // 5) Recent access log (proves our reads were logged)
  const log = credmgr.getAccessLog({ limit: 3 });
  console.log('\nRecent reads:');
  for (const entry of log) {
    console.log('  ' + entry.ts + '  ' + entry.source + '  ' + entry.name);
  }
}

main().catch((err) => {
  console.error('Example failed:', err.message);
  process.exit(1);
});
