// ADR-160: a 2FA seed read from a QR-code image in Add entry.  The fixtures (tests/fixtures/qr/, made by make-fixtures.mjs) are real
// PNGs: one holds an otpauth URI with an obviously fake secret, one a web address, one nothing.  They are decoded here with a small
// PNG reader (node:zlib) into the RGBA pixels a canvas would give, then through the real jsQR path in src/vault/qr-import.ts, and the
// Add entry logic is driven with the fixture broker so the shell's own preview types the field.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { inflateSync } from "node:zlib";
import { afterEach, describe, expect, it, vi } from "vitest";

import Component from "../../src/design/logic/core.js";
import {
  decodeQrImageFile,
  decodeQrPixels,
  isOtpauthUri,
  isPngOrJpeg,
  QR_IMAGE_MAX_BYTES,
  QrImportError,
  type ImageApi,
} from "../../src/vault/qr-import";
import { brokerScript } from "../fixtures/broker/script.mjs";
import { FAKE_URI, NOT_OTPAUTH } from "../fixtures/qr/make-fixtures.mjs";

const ROOT = resolve(__dirname, "../..");
const read = (rel: string) => readFileSync(resolve(ROOT, rel), "utf8");
const bytes = (name: string) => readFileSync(resolve(ROOT, "tests/fixtures/qr", name));
const g = globalThis as unknown as { window?: any };
const FAKE_SECRET = "FAKESECRETFORTESTSONLY22";

/** An 8-bit greyscale, non-interlaced PNG (what make-fixtures.mjs writes) as RGBA pixels. */
function pngToRgba(buf: Buffer): { data: Uint8ClampedArray; width: number; height: number } {
  let off = 8;
  let width = 0, height = 0;
  const idat: Buffer[] = [];
  while (off < buf.length) {
    const len = buf.readUInt32BE(off);
    const type = buf.toString("ascii", off + 4, off + 8);
    const body = buf.subarray(off + 8, off + 8 + len);
    if (type === "IHDR") {
      width = body.readUInt32BE(0);
      height = body.readUInt32BE(4);
      expect([body[8], body[9], body[12]]).toEqual([8, 0, 0]);
    } else if (type === "IDAT") idat.push(body);
    off += 12 + len;
  }
  const raw = inflateSync(Buffer.concat(idat));
  const data = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < height; y++) {
    expect(raw[y * (width + 1)]).toBe(0); // filter none
    for (let x = 0; x < width; x++) {
      const v = raw[y * (width + 1) + 1 + x];
      data.set([v, v, v, 255], (y * width + x) * 4);
    }
  }
  return { data, width, height };
}

/** A canvas and bitmap stand-in that hands back the fixture's pixels and records that it was cleaned up. */
function fakeApi(fixture: string) {
  const px = pngToRgba(bytes(fixture));
  const log = { cleared: false, closed: false, shrunk: false, drew: false, canvas: null as any };
  const api: ImageApi = {
    createImageBitmap: async () => ({ width: px.width, height: px.height, close: () => (log.closed = true) }) as unknown as ImageBitmap,
    createCanvas: (w, h) => {
      const image = { data: new Uint8ClampedArray(px.data), width: w, height: h };
      const canvas: any = {
        width: w,
        height: h,
        getContext: () => ({
          drawImage: () => (log.drew = true),
          getImageData: () => image,
          clearRect: () => (log.cleared = true),
        }),
      };
      log.canvas = canvas;
      (log as any).image = image;
      return canvas;
    },
  };
  return { api, log, image: () => (log as any).image as { data: Uint8ClampedArray } };
}

const pngBlob = (name: string) => new Blob([bytes(name)], { type: "image/png" });

afterEach(() => {
  delete g.window;
  vi.restoreAllMocks();
});

describe("decoding the fixture images (jsQR, in the page)", () => {
  it("reads the otpauth URI with the fake secret, and zeroes the pixels it was given", () => {
    const { data, width, height } = pngToRgba(bytes("totp-seed.png"));
    expect(decodeQrPixels(data, width, height)).toBe(FAKE_URI);
    expect(data.every((b) => b === 0)).toBe(true);
  });

  it("refuses a QR code that is not an authenticator URI, without repeating what it says", () => {
    const { data, width, height } = pngToRgba(bytes("not-otpauth.png"));
    let err: unknown;
    try {
      decodeQrPixels(data, width, height);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(QrImportError);
    expect((err as QrImportError).code).toBe("not_otpauth");
    expect(String((err as Error).message)).not.toContain("example.invalid");
    expect(data.every((b) => b === 0)).toBe(true);
  });

  it("says when there is no QR code at all", () => {
    const { data, width, height } = pngToRgba(bytes("blank.png"));
    expect(() => decodeQrPixels(data, width, height)).toThrow(QrImportError);
  });

  it("accepts only otpauth://totp/ and otpauth://hotp/ without control characters", () => {
    expect(isOtpauthUri(FAKE_URI)).toBe(true);
    expect(isOtpauthUri("OTPAUTH://TOTP/x?secret=A")).toBe(true);
    expect(isOtpauthUri("otpauth://hotp/x?secret=A&counter=1")).toBe(true);
    expect(isOtpauthUri(NOT_OTPAUTH)).toBe(false);
    expect(isOtpauthUri("otpauth://migration/offline?data=x")).toBe(false);
    expect(isOtpauthUri("otpauth://totp/x?secret=A\nB")).toBe(false);
    expect(isOtpauthUri("otpauth://totp/" + "a".repeat(5000))).toBe(false);
  });

  it("knows a PNG and a JPEG by their first bytes, not by their name or type", () => {
    expect(isPngOrJpeg(new Uint8Array(bytes("totp-seed.png").subarray(0, 8)))).toBe(true);
    expect(isPngOrJpeg(new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 0x10, 0x4a, 0x46]))).toBe(true);
    expect(isPngOrJpeg(new TextEncoder().encode("GIF89a.."))).toBe(false);
    expect(isPngOrJpeg(new Uint8Array([0x89, 0x50]))).toBe(false);
  });
});

describe("reading a file (bitmap, canvas, cleanup)", () => {
  it("returns the URI, and clears the canvas, shrinks it to 0 x 0, wipes the pixels and closes the bitmap", async () => {
    const { api, log, image } = fakeApi("totp-seed.png");
    expect(await decodeQrImageFile(pngBlob("totp-seed.png"), api)).toBe(FAKE_URI);
    expect(log.drew && log.cleared && log.closed).toBe(true);
    expect([log.canvas.width, log.canvas.height]).toEqual([0, 0]);
    expect(image().data.every((b) => b === 0)).toBe(true);
  });

  it("cleans up the same way when the image holds no seed", async () => {
    const { api, log } = fakeApi("not-otpauth.png");
    await expect(decodeQrImageFile(pngBlob("not-otpauth.png"), api)).rejects.toMatchObject({ code: "not_otpauth" });
    expect(log.cleared && log.closed).toBe(true);
    expect([log.canvas.width, log.canvas.height]).toEqual([0, 0]);
  });

  it("refuses what is not a PNG or JPEG, an empty file and a file over the limit, before decoding anything", async () => {
    const { api, log } = fakeApi("totp-seed.png");
    await expect(decodeQrImageFile(new Blob(["otpauth://totp/x?secret=A"], { type: "image/png" }), api)).rejects.toMatchObject({ code: "not_an_image" });
    await expect(decodeQrImageFile(new Blob([]), api)).rejects.toMatchObject({ code: "not_an_image" });
    const big = new Blob([bytes("totp-seed.png"), new Uint8Array(QR_IMAGE_MAX_BYTES)]);
    await expect(decodeQrImageFile(big, api)).rejects.toMatchObject({ code: "too_large" });
    expect(log.drew).toBe(false);
  });

  it("says an image the browser cannot open is unreadable", async () => {
    const api: ImageApi = {
      createImageBitmap: async () => {
        throw new Error("decode failed");
      },
      createCanvas: () => {
        throw new Error("not reached");
      },
    };
    await expect(decodeQrImageFile(pngBlob("totp-seed.png"), api)).rejects.toMatchObject({ code: "unreadable" });
  });
});

/** The fixture broker on a fake page, a logic instance with its state applied synchronously, and the Add entry dialog open. */
async function addEntryDialog() {
  const win: any = {};
  g.window = win;
  new Function("window", brokerScript({ locked: false }))(win);
  const calls: string[] = [];
  const inner = win.__TAURI_INTERNALS__.invoke;
  win.__TAURI_INTERNALS__.invoke = async (cmd: string, args: Record<string, unknown> = {}) => {
    calls.push(cmd);
    return inner(cmd, args);
  };
  const logic: any = new (Component as any)({ mode: "pro" });
  logic.__host = {
    setLogicState(update: any, cb?: () => void) {
      const patch = typeof update === "function" ? update(logic.state) : update;
      if (patch) logic.state = { ...logic.state, ...patch };
      cb?.();
    },
    forceUpdate() {},
  };
  const notes: [string, string][] = [];
  logic.notify = (k: string, t: string) => notes.push([k, t]);
  await logic.model.boot();
  logic.state = { ...logic.state, screen: "app", selected: "atlas" };
  logic._mounted = true; // the form wipe on close runs only for a mounted logic
  logic.openAddDlg("atlas");
  return { logic, notes, calls };
}

const flush = async (ms = 400) => new Promise((r) => setTimeout(r, ms));

describe("Add entry: a QR image puts the seed in the form, and nothing else", () => {
  it("fills the first empty value box with the URI, the preview types it a 2FA seed, and nothing is written or logged", async () => {
    const { logic, notes, calls } = await addEntryDialog();
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((m) => vi.spyOn(console, m));
    logic._qrImageApi = fakeApi("totp-seed.png").api;
    const input = { files: [pngBlob("totp-seed.png")], value: "C:\\fakepath\\totp-seed.png" };
    await logic.onQrFileChosen({ target: input });
    expect(input.value).toBe(""); // the same file can be chosen again
    expect(logic.state.singleFields).toEqual([{ label: "", value: FAKE_URI }]);
    expect(logic.renderVals().qrReadShow).toBe(true);
    await flush();
    const seg = logic.state.preview.segs[0];
    expect(seg.fields[0].type).toBe("totp-seed"); // the shell's preview, exactly as for a pasted URI
    expect(calls).toContain("fields_preview");
    expect(calls.filter((c) => c.startsWith("entry_create"))).toEqual([]); // nothing saved
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    expect(JSON.stringify(notes)).not.toContain(FAKE_SECRET);
  });

  it("adds a new field when every value box is taken, and keeps what was typed", async () => {
    const { logic } = await addEntryDialog();
    logic.state = { ...logic.state, singleFields: [{ label: "user", value: "someone" }] };
    logic._qrImageApi = fakeApi("totp-seed.png").api;
    await logic.importQrImage(pngBlob("totp-seed.png"));
    expect(logic.state.singleFields).toEqual([{ label: "user", value: "someone" }, { label: "", value: FAKE_URI }]);
  });

  it("a drop takes the first file and keeps the webview from opening it", async () => {
    const { logic } = await addEntryDialog();
    logic._qrImageApi = fakeApi("totp-seed.png").api;
    const ev = { preventDefault: vi.fn(), dataTransfer: { files: [pngBlob("totp-seed.png")] } };
    await logic.onQrDrop(ev);
    expect(ev.preventDefault).toHaveBeenCalled();
    expect(logic.state.singleFields[0].value).toBe(FAKE_URI);
  });

  it("a QR code that is not a seed is refused in words, beside the control, and the form is unchanged", async () => {
    const { logic } = await addEntryDialog();
    logic._qrImageApi = fakeApi("not-otpauth.png").api;
    await logic.importQrImage(pngBlob("not-otpauth.png"));
    expect(logic.state.singleFields).toEqual([{ label: "", value: "" }]);
    const v = logic.renderVals();
    expect(v.qrErrShow).toBe(true);
    expect(v.qrErr).toContain("not an authenticator code");
    expect(v.qrErr).not.toContain("example.invalid");
    expect(v.qrReadShow).toBe(false);
  });

  it("a seed decoded after the dialog closed is dropped, not put into a form nobody sees", async () => {
    const { logic } = await addEntryDialog();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const slow = fakeApi("totp-seed.png").api;
    logic._qrImageApi = { ...slow, createImageBitmap: async (f: Blob) => (await gate, slow.createImageBitmap(f)) };
    const pending = logic.importQrImage(pngBlob("totp-seed.png"));
    logic.state = { ...logic.state, dialog: null };
    release();
    await pending;
    expect(logic.state.singleFields.some((f: { value: string }) => f.value === FAKE_URI)).toBe(false);
  });

  it("closing the dialog wipes the decoded seed with the rest of the form", async () => {
    const { logic } = await addEntryDialog();
    logic._qrImageApi = fakeApi("totp-seed.png").api;
    await logic.importQrImage(pngBlob("totp-seed.png"));
    logic.state = { ...logic.state, dialog: null };
    logic.renderVals();
    await flush(10);
    expect(logic.state.singleFields).toEqual([{ label: "", value: "" }]);
    expect(logic.state.qrRead).toBe(false);
  });
});

describe("the sources keep the image and the seed in the page", () => {
  it("qr-import.ts and the Add entry logic never log, store, fetch or make a URL of an image", () => {
    for (const rel of ["src/vault/qr-import.ts", "src/design/logic/write.js"]) {
      const src = read(rel);
      expect(src, rel).not.toMatch(/console\.|localStorage|sessionStorage|indexedDB|createObjectURL|readAsDataURL|toDataURL|toBlob\(|fetch\(|XMLHttpRequest/);
    }
  });

  it("the control takes PNG and JPEG only, and has a drop zone", () => {
    const html = read("src/design/screens/S6-add-entry.html");
    expect(html).toContain('accept="image/png,image/jpeg"');
    expect(html).toContain('onDrop="{{onQrDrop}}"');
    expect(html).toContain('onDragOver="{{onQrDragOver}}"');
  });

  it("jsQR is a pinned dependency from the registry, with its integrity in the lock file", () => {
    const pkg = JSON.parse(read("package.json"));
    expect(pkg.dependencies.jsqr).toBe("1.4.0");
    const lock = JSON.parse(read("package-lock.json"));
    expect(lock.packages["node_modules/jsqr"]).toMatchObject({
      version: "1.4.0",
      resolved: "https://registry.npmjs.org/jsqr/-/jsqr-1.4.0.tgz",
      license: "Apache-2.0",
    });
    expect(lock.packages["node_modules/jsqr"].integrity).toMatch(/^sha512-/);
  });
});
