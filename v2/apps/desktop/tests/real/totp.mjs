/**
 * RFC 6238 TOTP (SHA-1, 6 digits, 30 s), enough to act as the authenticator app the second-factor journeys need.
 *
 * The broker accepts a code from one step either side of now and refuses a step it has already accepted (a replay ledger), so
 * {@link Authenticator.next} hands out the earliest step in that window that has not been used yet, and waits for the clock to
 * open one when all three have been spent. The secret is read from the page (the wizard shows it as text) or from the otpauth URI.
 */
import { createHmac, randomBytes } from "node:crypto";

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(text) {
  const clean = text.replace(/[\s=-]/g, "").toUpperCase();
  let bits = "";
  for (const ch of clean) {
    const v = BASE32.indexOf(ch);
    if (v < 0) throw new Error(`not base32: ${ch}`);
    bits += v.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

/** Base32 text for `bytes` (RFC 4648, no padding): the form an authenticator app is given. */
export function base32Encode(bytes) {
  let bits = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i < bits.length; i += 5) out += BASE32[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  return out;
}

/**
 * A fresh TOTP seed for a fixture entry: 20 random bytes (the length RFC 4226 recommends for SHA-1), as 32 base32 characters.
 * Generated per call, never written down: a literal seed in a spec is a secret-shaped string in a tracked file (and the RFC's own
 * example seed is the one every secret scanner already knows).
 */
export function randomTotpSeed() {
  const bytes = randomBytes(20);
  const text = base32Encode(bytes);
  if (text.length !== 32 || !base32Decode(text).equals(bytes)) throw new Error("randomTotpSeed: base32 round trip failed");
  return text;
}

/** The code for RFC 6238 counter `step`. */
export function codeAt(secret, step) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const h = createHmac("sha1", secret).update(counter).digest();
  const o = h[h.length - 1] & 0x0f;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1_000_000).padStart(6, "0");
}

export class Authenticator {
  #secret;
  #used = new Set();

  /** @param {string} secret  base32 text (spaces allowed) or an otpauth:// URI */
  constructor(secret) {
    const m = /[?&]secret=([A-Za-z2-7=]+)/.exec(secret);
    this.#secret = base32Decode(m ? m[1] : secret);
  }

  /** A code the broker will accept now and has not seen: waits at most one step for the clock to open one. */
  async next() {
    for (let attempt = 0; attempt < 400; attempt++) {
      const now = Math.floor(Date.now() / 1000 / 30);
      for (const step of [now - 1, now, now + 1]) {
        if (!this.#used.has(step)) {
          this.#used.add(step);
          return codeAt(this.#secret, step);
        }
      }
      await new Promise((r) => setTimeout(r, 250));
    }
    throw new Error("no unused TOTP step opened within 100 s");
  }

  /** A code that is well-formed but wrong for every step the broker would accept. */
  wrong() {
    const now = Math.floor(Date.now() / 1000 / 30);
    const taken = new Set([now - 2, now - 1, now, now + 1, now + 2].map((s) => codeAt(this.#secret, s)));
    for (let n = 0; n < 1_000_000; n += 1) {
      const c = String(n).padStart(6, "0");
      if (!taken.has(c)) return c;
    }
    throw new Error("unreachable");
  }
}
