// ADR-160: regenerates the QR-image fixtures for tests/unit/qr-import.test.ts.  Run from v2/apps/desktop:
//   node tests/fixtures/qr/make-fixtures.mjs
// Each image is an 8-bit greyscale PNG (no interlace, filter 0) drawn from `qrcode-generator` (already a dependency).  The
// secret in totp-seed.png is FAKE and says so; it opens nothing.  The PNG writer is the standard one: signature, IHDR, IDAT
// (zlib), IEND, each chunk with its CRC-32.
import { writeFileSync } from "node:fs";
import { deflateSync } from "node:zlib";
import qrcode from "qrcode-generator";

export const FAKE_URI = "otpauth://totp/CredMgr%20Fixture:nobody%40example.invalid?secret=FAKESECRETFORTESTSONLY22&issuer=CredMgr%20Fixture";
export const NOT_OTPAUTH = "https://example.invalid/this-is-not-a-2fa-seed";

const CRC = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
const chunk = (type, data) => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
};

/** A greyscale PNG of `size` x `size` pixels whose value is `pixel(x, y)` (0 black, 255 white). */
function png(size, pixel) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 0; // greyscale
  const raw = Buffer.alloc((size + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size + 1)] = 0; // filter: none
    for (let x = 0; x < size; x++) raw[y * (size + 1) + 1 + x] = pixel(x, y);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

/** `text` as a QR code, 6 pixels a module, 4 modules of quiet zone. */
function qrPng(text) {
  const qr = qrcode(0, "M");
  qr.addData(text, "Byte");
  qr.make();
  const n = qr.getModuleCount(), quiet = 4, scale = 6, size = (n + quiet * 2) * scale;
  return png(size, (x, y) => {
    const c = Math.floor(x / scale) - quiet, r = Math.floor(y / scale) - quiet;
    return c >= 0 && r >= 0 && c < n && r < n && qr.isDark(r, c) ? 0 : 255;
  });
}

const dir = new URL(".", import.meta.url);
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop())) {
  writeFileSync(new URL("totp-seed.png", dir), qrPng(FAKE_URI));
  writeFileSync(new URL("not-otpauth.png", dir), qrPng(NOT_OTPAUTH));
  writeFileSync(new URL("blank.png", dir), png(120, () => 255));
  console.log("wrote totp-seed.png, not-otpauth.png, blank.png");
}
