#!/usr/bin/env node
/**
 * Seals the TEST extras pack: the same data tables as the real pack (shapes, global colour, link colour, entry-dot hue ranges,
 * backdrops) under a code that exists only for tests, in the format src/design/logic/extras.js reads (AES-256-GCM, key from
 * PBKDF2-SHA-256 at 200 000 rounds of the upper-case code with no whitespace).
 *
 *   node tests/fixtures/extras/seal-test-pack.mjs        # prints the JSON blob; paste it into TEST_BLOB in extras.js
 *
 * The real pack is sealed by the owner in the design project under a code this repository never contains.  A test build
 * (vite --mode test) opens THIS blob instead, with TEST_CODE below; a release build does not contain it (scripts/dc/release-bans.mjs).
 */
import { webcrypto as crypto, randomBytes } from "node:crypto";

export const TEST_CODE = "TEST-EXTRAS-CODE";

export const TEST_PACK = {
  v: 1,
  shapes: {
    hexagon: { n: 6, rot: -90 }, octagon: { n: 8, rot: -67.5 }, diamond: { n: 4, rot: -90 },
    square: { half: 0.72, corner: 0.22 },
  },
  global: { sig: "sig", ash: "ash", tint: "tint" },
  link: { ash: "ash", bone: "bone@0.5", sig: "sig@0.7" },
  dots: { cool: [160, 260], warm: [20, 80], mono: 0 },
  backdrop: { dots: { k: "dots", step: 40 }, lines: { k: "lines", step: 40 }, rings: { k: "rings", step: 60 } },
};

export async function seal(code = TEST_CODE, pack = TEST_PACK) {
  const b64 = (u) => Buffer.from(u).toString("base64");
  const salt = randomBytes(16), iv = randomBytes(12), it = 200000;
  const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(code.replace(/\s+/g, "").toUpperCase()), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: it, hash: "SHA-256" }, km, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(pack)));
  return JSON.stringify({ v: 1, it, salt: b64(salt), iv: b64(iv), d: b64(new Uint8Array(ct)) });
}

if (import.meta.url === `file://${process.argv[1]}`) console.log(await seal());
