/**
 * ADR-160: read an authenticator seed out of a QR-code image, in the page, with no network.
 *
 * A PNG or JPEG the person picks (or drops) is decoded here with `jsQR` (Apache-2.0, a dependency bundled into the app: the
 * strict CSP rules out any remote script, and nothing here fetches anything).  The only thing that leaves this module is the
 * `otpauth://` URI the code holds, and it goes into the Add entry form's value box exactly as if it had been pasted there, so
 * the shell's preview, the broker and the stored entry see what they see today for a pasted URI.
 *
 * What the image and the seed must never do: reach the disk, a log or the developer console: the file is read into an `ImageBitmap`
 * (no object URL, no `data:` URL, no `<img>` in the page), drawn on a canvas that is never attached to the document, and its
 * pixels are read once.  Afterwards the pixel buffer and jsQR's byte copy are overwritten with zeros, the canvas is cleared and
 * shrunk to 0 x 0, and the bitmap is closed.  JavaScript strings cannot be wiped, so the decoded text lives until it is
 * collected, exactly as a pasted value does.  An error never carries what the image held: only a code from `QrImportCode`.
 */
import jsQR from "jsqr";

/** Why an image gave no seed.  The page turns each into a sentence; none carries the image's content. */
export type QrImportCode = "not_an_image" | "too_large" | "unreadable" | "no_qr" | "not_otpauth";

export class QrImportError extends Error {
  readonly code: QrImportCode;
  constructor(code: QrImportCode) {
    super(QR_IMPORT_TEXT[code]);
    this.name = "QrImportError";
    this.code = code;
  }
}

/** The sentence for each code, as the Add entry dialog shows it. */
export const QR_IMPORT_TEXT: Record<QrImportCode, string> = {
  not_an_image: "That file is not a PNG or JPEG image.",
  too_large: "That image is larger than 8 MiB.",
  unreadable: "That image could not be read.",
  no_qr: "No QR code was found in that image. Try a sharper or larger picture of it.",
  not_otpauth: "That QR code is not an authenticator code (it does not start with otpauth://). Nothing was added.",
};

/** The largest file read at all. */
export const QR_IMAGE_MAX_BYTES = 8 * 1024 * 1024;
/** Images are scaled down so their longer side is at most this many pixels before decoding (bounds memory and time). */
export const QR_MAX_SIDE = 2048;
/** The longest URI accepted; a real otpauth URI is well under 1 KiB. */
export const OTPAUTH_MAX_CHARS = 4096;

const PNG_MAGIC = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const JPEG_MAGIC = [0xff, 0xd8, 0xff];

/** Whether the first bytes are a PNG or JPEG signature.  The file's own `type` is not trusted: a drop may carry none. */
export function isPngOrJpeg(head: Uint8Array): boolean {
  const starts = (sig: number[]) => sig.every((b, i) => head[i] === b);
  return head.length >= 8 && (starts(PNG_MAGIC) || starts(JPEG_MAGIC));
}

/** Whether `text` is an authenticator URI this app imports: `otpauth://totp/` or `otpauth://hotp/`, no control characters. */
export function isOtpauthUri(text: string): boolean {
  return (
    text.length <= OTPAUTH_MAX_CHARS &&
    /^otpauth:\/\/(totp|hotp)\//i.test(text) &&
    !/[\u0000-\u001f\u007f]/.test(text)
  );
}

/**
 * Decode RGBA pixels and return the otpauth URI they show.  The buffer is overwritten with zeros before this returns, whatever
 * the outcome.  Throws `QrImportError` (`no_qr` or `not_otpauth`).
 */
export function decodeQrPixels(rgba: Uint8ClampedArray, width: number, height: number): string {
  let found: ReturnType<typeof jsQR> = null;
  try {
    found = jsQR(rgba, width, height, { inversionAttempts: "attemptBoth" });
  } finally {
    rgba.fill(0);
  }
  if (!found) throw new QrImportError("no_qr");
  const text = found.data;
  found.binaryData.fill(0);
  found.chunks.length = 0;
  found = null;
  if (!isOtpauthUri(text)) throw new QrImportError("not_otpauth");
  return text;
}

/** What `decodeQrImageFile` needs from the browser; injectable so the flow is testable without a real canvas. */
export interface ImageApi {
  createImageBitmap(file: Blob): Promise<ImageBitmap>;
  createCanvas(width: number, height: number): HTMLCanvasElement | OffscreenCanvas;
}

const browserApi: ImageApi = {
  createImageBitmap: (file) => createImageBitmap(file),
  createCanvas: (width, height) => {
    if (typeof OffscreenCanvas !== "undefined") return new OffscreenCanvas(width, height);
    const c = document.createElement("canvas"); // never attached to the document
    c.width = width;
    c.height = height;
    return c;
  },
};

/** Read a picked or dropped image file and return the otpauth URI in it.  Throws `QrImportError`. */
export async function decodeQrImageFile(file: Blob, api: ImageApi = browserApi): Promise<string> {
  if (!file || file.size === 0) throw new QrImportError("not_an_image");
  if (file.size > QR_IMAGE_MAX_BYTES) throw new QrImportError("too_large");
  let head: Uint8Array;
  try {
    head = new Uint8Array(await file.slice(0, 8).arrayBuffer());
  } catch {
    throw new QrImportError("unreadable");
  }
  if (!isPngOrJpeg(head)) throw new QrImportError("not_an_image");

  let bitmap: ImageBitmap | null = null;
  let canvas: HTMLCanvasElement | OffscreenCanvas | null = null;
  let ctx: CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D | null = null;
  try {
    try {
      bitmap = await api.createImageBitmap(file);
    } catch {
      throw new QrImportError("unreadable");
    }
    const scale = Math.min(1, QR_MAX_SIDE / Math.max(bitmap.width, bitmap.height, 1));
    const width = Math.max(1, Math.round(bitmap.width * scale));
    const height = Math.max(1, Math.round(bitmap.height * scale));
    canvas = api.createCanvas(width, height);
    ctx = canvas.getContext("2d", { willReadFrequently: true }) as CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D | null;
    if (!ctx) throw new QrImportError("unreadable");
    ctx.drawImage(bitmap, 0, 0, width, height);
    const image = ctx.getImageData(0, 0, width, height);
    return decodeQrPixels(image.data, width, height);
  } finally {
    if (ctx && canvas) ctx.clearRect(0, 0, canvas.width, canvas.height);
    if (canvas) {
      canvas.width = 0;
      canvas.height = 0;
    }
    if (bitmap) bitmap.close();
  }
}
