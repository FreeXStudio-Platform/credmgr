/* Browser-storage helpers (decision D10).

   The app writes a handful of non-secret preferences to the webview's local storage.  Nothing that names a vault
   object may be written there in clear: node ids are often project names, and WebKit keeps local storage on disk in
   plain files.  Positions are therefore stored under a hash of the id, never the id.

   Every key the app writes (PRIVACY.md lists them; keep the two in step):
     credmgr_gposV       layout format version ("3")                                   - no ids
     credmgr_gpos        node positions, keyed by hid("n", nodeId)                      - hashed ids
     credmgr_gposEntry   entry-dot positions, keyed by hid("e", entryId)                - hashed ids
     credmgr_cosmetics   the cosmetic choices (mark, glyph weight, halo, badge, shape, colours, ...) - option names only; extras.js
     credmgr_donate_unlocked  "1" once a supporter code has opened the extras             - a flag; extras.js
     credmgr_extras_key  the AES key (base64) that opens the sealed extras on this device - key material for cosmetic data only; extras.js
     credmgr_usage       calendar days with an unlock, which asks were shown, opt-out,   - dates and flags; never a time, a name,
                         the day each free milestone was reached                           a count or an id; extras.js
     credmgr_keys        "off" only when single-key shortcuts are turned off            - a flag
     credpong_best       best CredPong score                                            - no ids
     credpong_level      highest CredPong level reached                                 - no ids
     credgames.<game>.best / .level   the same for each further CredGames title         - no ids (none ships yet)
     credmgr_prefs       the settings (theme, colour, contrast, motion, auto-lock, ...)  - no ids; src/vault/prefs.ts

   The hash only keeps names out of the clear.  Ids are low-entropy, so it is not a defence against someone who can
   already read the profile directory and guess project names; nothing secret is stored here either way. */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const rotr = (x, n) => (x >>> n) | (x << (32 - n));

/** SHA-256 of a string (UTF-8), as lower-case hex.  Synchronous, because positions are read while the graph is built. */
export function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const bitLen = bytes.length * 8;
  const padded = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
  view.setUint32(padded.length - 4, bitLen >>> 0);

  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const w = new Uint32Array(64);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  return [...H].map((x) => x.toString(16).padStart(8, "0")).join("");
}

/** The storage key for a vault object: 16 hex characters, domain-separated by kind ("n" node, "e" entry). */
export function hid(kind, id) {
  return sha256Hex(`credmgr:${kind}:${id}`).slice(0, 16);
}
