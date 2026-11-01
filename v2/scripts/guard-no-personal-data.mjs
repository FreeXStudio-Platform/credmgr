#!/usr/bin/env node
/**
 * guard-no-personal-data — blocks a contributor's own machine leaking into the
 * design corpus or the product source.
 *
 * This is deliberately STRUCTURAL, not a denylist. A denylist of "these specific
 * project names/paths are forbidden" would itself have to spell out the private
 * names it exists to keep out of a public repository — the same reasoning
 * `v1/tests/classify.test.js` already applied to `lib/classify.js`'s built-in
 * rules. Instead this recognises the *shape* of a personal absolute home-directory
 * path (`/Users/<name>/…`, `/home/<name>/…`, `C:\Users\<name>\…`), of a contactable
 * email address on a non-documentation domain, and of a routable IPv4 literal — each of
 * which flags any contributor's accidental leak, not just one person's, and never has to
 * name anyone or anything to do it.
 *
 * The two non-path rules were added 2026-08-18 after `docs/22_ORG_VAULT_SYNC_AND_LICENSING.md`
 * was found carrying a real billing address on a real brand domain while this guard reported
 * clean — it had only ever checked home paths, so three of the four things `SESSION_PROTOCOL.md`
 * rule 6.5 forbids (a project name, a server, a username) were unenforced. The IPv4 rule is the
 * mechanical form of the check that caught a production VPS address by hand in Session 20.
 *
 * Usage:
 *   node scripts/guard-no-personal-data.mjs            # scan staged changes (pre-commit)
 *   node scripts/guard-no-personal-data.mjs --all      # scan the whole working tree (CI)
 *   node scripts/guard-no-personal-data.mjs --install  # install the git pre-commit hook
 *
 * Exit codes: 0 clean · 1 findings · 2 usage/environment error.
 *
 * DESIGN NOTES
 * - Fails CLOSED, same as guard-no-secrets.mjs: an unreadable/unresolvable file
 *   set blocks rather than passing silently.
 * - `BUILD_LOG.md` is exempt: it is an append-only, dated session diary that
 *   deliberately quotes real captured command output as gate evidence (the
 *   project's own evidence discipline — see `SESSION_PROTOCOL.md` §5). Scrubbing
 *   incidental paths out of historical evidence would falsify the record; the
 *   portfolio convention this repo follows is to leave dated history untouched
 *   and fix the leak at its source instead.
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, statSync, writeFileSync, chmodSync, mkdirSync, existsSync } from 'node:fs';
import path from 'node:path';

const MAX_BYTES = 2 * 1024 * 1024;
const ALLOW_MARK = 'credmgr-allow';
const ALLOW_WINDOW = 5;

// Files that are dated history, not shipped design/product content — never rewritten.
const HISTORY_FILES = [
  /(^|\/)BUILD_LOG\.md$/,
];

// Files where a *pattern definition* legitimately looks like a personal path.
const PATTERN_SOURCE_FILES = [
  /(^|\/)scripts\/guard-no-personal-data\.mjs$/,
  /(^|\/)scripts\/guard-no-secrets\.mjs$/,
];

// Generic placeholder usernames that are fine in example commands — not a leak.
// A single character (test fixtures commonly use "x", "a", "b") is always generic.
const ALLOWED_USERNAMES = new Set([
  'runner', 'user', 'username', 'you', 'yourname', 'youruser', 'me', 'name', 'alice', 'bob',
]);
const isGenericUsername = (u) => u.length <= 1 || ALLOWED_USERNAMES.has(u.toLowerCase());

// RFC 2606 / RFC 6761 reserved documentation domains. Anything else is a *contactable*
// address: publishing one links this repository to a real person or organisation, which is
// the same leak class as a home-directory path. Kept structural (a reserved-domain allowlist),
// never a denylist of the real domains — those must not appear in this file either.
const RESERVED_EMAIL_DOMAINS = new Set(['example.com', 'example.net', 'example.org']);
const RESERVED_EMAIL_TLDS = ['.example', '.test', '.invalid', '.localhost'];
// `128x128@2x.png`-style asset filenames match the email shape but are not addresses.
const ASSET_EXTENSIONS = /\.(?:png|jpe?g|gif|svg|webp|ico|avif|bmp|tiff?)$/i;

// The ONE published project contact address, carried only as sha256(lower-case address) so the
// address is never spelled out in this file. It mirrors `email-address.allowed_sha256` in
// tools/public-export/rules/leak-classes.json; every other address on a real domain stays a finding.
const PUBLISHED_CONTACT_SHA256 = new Set(['5d39b75a58dc9de0ba11fc4557b22ebc47188174b8c8d356337656e9e42ef539']);
const isPublishedContact = (address) => PUBLISHED_CONTACT_SHA256.has(createHash('sha256').update(address.toLowerCase()).digest('hex'));

const isReservedEmailDomain = (domain) => {
  const d = domain.toLowerCase();
  if (ASSET_EXTENSIONS.test(d)) return true;
  if (RESERVED_EMAIL_DOMAINS.has(d)) return true;
  return RESERVED_EMAIL_TLDS.some(tld => d.endsWith(tld));
};

// True only for an address that would actually route on the public internet. Documentation
// (RFC 5737), private (RFC 1918), loopback, link-local, CGNAT, benchmarking, multicast and
// reserved space all read as intentional examples, not as a leak of real infrastructure.
// This is the rule that would have caught the production VPS address found in the design
// bundle on 2026-08-18 by hand (see BUILD_LOG.md Session 20).
const isRoutableIPv4 = (literal) => {
  const octets = literal.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => !Number.isInteger(o) || o < 0 || o > 255)) return false;
  const [a, b] = octets;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;            // this-network, private, loopback, multicast+
  if (a === 169 && b === 254) return false;                                   // link-local
  if (a === 172 && b >= 16 && b <= 31) return false;                          // private
  if (a === 192 && b === 168) return false;                                   // private
  if (a === 100 && b >= 64 && b <= 127) return false;                         // CGNAT (RFC 6598)
  if (a === 198 && (b === 18 || b === 19)) return false;                      // benchmarking (RFC 2544)
  if (a === 192 && b === 0 && octets[2] === 2) return false;                  // TEST-NET-1
  if (a === 198 && b === 51 && octets[2] === 100) return false;               // TEST-NET-2
  if (a === 203 && b === 0 && octets[2] === 113) return false;                // TEST-NET-3
  return true;
};

const CONTENT_RULES = [
  {
    id: 'contact-email-real-domain',
    re: /\b[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b/g,
    matches: (m) => !isReservedEmailDomain(m[1]) && !isPublishedContact(m[0]),
    why: 'a contactable email address on a real domain — use an RFC 2606 documentation domain',
  },
  {
    id: 'routable-ip-literal',
    re: /\b((?:\d{1,3}\.){3}\d{1,3})\b/g,
    matches: (m) => isRoutableIPv4(m[1]),
    why: 'a routable IPv4 address — use an RFC 5737 documentation address (203.0.113.x)',
  },

  {
    id: 'home-path-unix',
    re: /\/(?:Users|home)\/([A-Za-z0-9_.-]+)\//g,
    matches: (m) => !isGenericUsername(m[1]),
    why: 'a real machine\'s absolute home-directory path',
  },
  {
    id: 'home-path-windows',
    re: /[A-Za-z]:\\\\?Users\\\\?([A-Za-z0-9_.-]+)\\\\?/g,
    matches: (m) => !isGenericUsername(m[1]),
    why: 'a real machine\'s absolute home-directory path (Windows)',
  },
];

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
}

function stagedFiles() {
  try {
    return git(['diff', '--cached', '--name-only', '--diff-filter=ACMR'])
      .split('\n').map(s => s.trim()).filter(Boolean);
  } catch {
    console.error('guard-no-personal-data: not a git repository, or git is unavailable.');
    process.exit(2);
  }
}

function trackedFiles() {
  try {
    const tracked = git(['ls-files']).split('\n');
    const untracked = git(['ls-files', '--others', '--exclude-standard']).split('\n');
    const set = new Set([...tracked, ...untracked].map(s => s.trim()).filter(Boolean));
    return [...set];
  } catch {
    console.error('guard-no-personal-data: not a git repository, or git is unavailable.');
    process.exit(2);
  }
}

function scan(files) {
  const findings = [];

  for (const file of files) {
    if (HISTORY_FILES.some(re => re.test(file))) continue;

    let text;
    try {
      const st = statSync(file);
      if (!st.isFile() || st.size > MAX_BYTES) continue;
      text = readFileSync(file, 'utf8');
    } catch { continue; }
    if (text.includes('\0')) continue; // binary

    const isPatternSource = PATTERN_SOURCE_FILES.some(re => re.test(file));
    if (isPatternSource) continue;

    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      let allowed = false;
      for (let j = Math.max(0, i - ALLOW_WINDOW); j <= i; j++) {
        if (lines[j].includes(ALLOW_MARK)) { allowed = true; break; }
      }
      if (allowed) continue;

      for (const rule of CONTENT_RULES) {
        rule.re.lastIndex = 0;
        let m;
        while ((m = rule.re.exec(line)) !== null) {
          if (rule.matches(m)) {
            findings.push({ file, line: i + 1, rule: rule.id, why: rule.why });
            break; // one finding per rule per line is enough
          }
        }
      }
    }
  }
  return findings;
}

function installHook() {
  let gitDir;
  try { gitDir = git(['rev-parse', '--git-dir']).trim(); }
  catch { console.error('guard-no-personal-data: not a git repository.'); process.exit(2); }

  const hooksDir = path.join(gitDir, 'hooks');
  mkdirSync(hooksDir, { recursive: true });
  const hookPath = path.join(hooksDir, 'pre-commit');

  const line = 'node "$(git rev-parse --show-toplevel)/v2/scripts/guard-no-personal-data.mjs" || exit 1\n';

  if (existsSync(hookPath)) {
    const existing = readFileSync(hookPath, 'utf8');
    if (existing.includes('guard-no-personal-data')) {
      console.log('pre-commit hook already installed.');
      return;
    }
    writeFileSync(hookPath, existing + line);
    console.log('✓ appended guard-no-personal-data to existing pre-commit hook at ' + hookPath);
    return;
  }

  writeFileSync(hookPath,
    '#!/bin/sh\n' +
    '# installed by credmgr — blocks commits leaking a contributor\'s home directory\n' +
    line);
  chmodSync(hookPath, 0o755);
  console.log('✓ pre-commit hook installed at ' + hookPath);
}

const argv = process.argv.slice(2);
if (argv.includes('--install')) { installHook(); process.exit(0); }

const all = argv.includes('--all');
const files = all ? trackedFiles() : stagedFiles();

if (!all && files.length === 0) process.exit(0);

const findings = scan(files);

if (findings.length === 0) {
  console.log(`guard-no-personal-data: ✓ clean (${files.length} file${files.length === 1 ? '' : 's'} scanned)`);
  process.exit(0);
}

console.error('\n╔══════════════════════════════════════════════════════════════════╗');
console.error('║  COMMIT BLOCKED — a personal machine path was found               ║');
console.error('╚══════════════════════════════════════════════════════════════════╝\n');
for (const f of findings) {
  console.error(`  ${f.file}:${f.line}`);
  console.error(`      rule: ${f.rule} — ${f.why}\n`);
}
console.error('What to do:');
console.error('  • Replace it with a generic placeholder (e.g. `path/to/CredMgr`, `<repo-root>`).');
console.error('  • Historical evidence output? It belongs in BUILD_LOG.md, which is exempt.');
console.error('  • False positive? Put a `' + ALLOW_MARK + '` comment on that line, or in a');
console.error('                    comment within the 5 lines above it, saying WHY it is safe.\n');
process.exit(1);
