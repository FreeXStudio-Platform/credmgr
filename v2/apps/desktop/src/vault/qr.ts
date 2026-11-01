/**
 * A QR code for the authenticator enrolment, rendered locally.
 *
 * The otpauth URI carries the second-factor secret, so it is encoded here, in the page, with a library that has no network
 * code (`qrcode-generator`, MIT).  No remote QR service is ever involved.  The result is one SVG path, which the template draws
 * as `<path d="…">`: the page never builds markup from the URI.
 */
import qrcode from "qrcode-generator";

/** Modules of white around the code.  The QR specification asks for 4; scanners are far less forgiving without it. */
export const QUIET_ZONE = 4;

export interface QrPath {
  /** The side of the square viewBox, quiet zone included. */
  size: number;
  /** One path of 1-module-high runs (`M x,y h n v1 h -n z`), in viewBox units. */
  d: string;
}

/** Encode `text` (byte mode, error correction M) as an SVG path.  Throws if the text does not fit the largest QR version. */
export function qrPath(text: string): QrPath {
  const qr = qrcode(0, "M"); // 0: pick the smallest version that fits
  qr.addData(text, "Byte");
  qr.make();
  const n = qr.getModuleCount();
  const runs: string[] = [];
  for (let row = 0; row < n; row++) {
    let col = 0;
    while (col < n) {
      if (!qr.isDark(row, col)) {
        col++;
        continue;
      }
      let end = col;
      while (end < n && qr.isDark(row, end)) end++;
      runs.push(`M${col + QUIET_ZONE},${row + QUIET_ZONE}h${end - col}v1h-${end - col}z`);
      col = end;
    }
  }
  return { size: n + QUIET_ZONE * 2, d: runs.join("") };
}

/** The matrix a path draws, for tests: `true` where a module is dark. */
export function pathToMatrix(p: QrPath): boolean[][] {
  const n = p.size - QUIET_ZONE * 2;
  const m: boolean[][] = Array.from({ length: n }, () => new Array<boolean>(n).fill(false));
  for (const run of p.d.matchAll(/M(\d+),(\d+)h(\d+)v1h-\d+z/g)) {
    const [x, y, len] = [Number(run[1]) - QUIET_ZONE, Number(run[2]) - QUIET_ZONE, Number(run[3])];
    for (let i = 0; i < len; i++) m[y][x + i] = true;
  }
  return m;
}

/**
 * The shared secret out of an otpauth URI, grouped in fours for typing into an authenticator by hand
 * (`otpauth://totp/CredMgr:global?secret=…&issuer=CredMgr&period=30&digits=6`).  `""` when the URI has none.
 */
export function otpSecretOf(uri: string): string {
  const m = /[?&]secret=([A-Za-z0-9=]+)/.exec(uri);
  if (!m) return "";
  return (m[1].replace(/=+$/, "").match(/.{1,4}/g) ?? []).join(" ");
}
