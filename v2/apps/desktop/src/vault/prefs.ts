/**
 * Preferences (work package D): the settings a user picks, remembered in the webview's local storage.
 *
 * ONE key, {@link PREFS_KEY}.  It is listed in all three places that list the app's storage: the DOCUMENTED list in
 * tests/unit/pstore.test.ts, the header comment in src/design/logic/pstore.js, and PRIVACY.md.
 *
 * A pref is a setting, never a vault object: no node or entry id or name goes in it, hashed or not (the graph layout is
 * different: it is keyed by an id, so it goes through pstore's `hid()`).  The shape below is the whole of what can be
 * stored, and {@link pick} drops anything else, so a corrupt or hand-edited value can neither crash the app nor smuggle a
 * string into a setting.  A secret has no place here either; nothing in this file ever sees one.
 *
 * Storage is best effort.  A webview with storage blocked, a full quota or a private window means "nothing is
 * remembered", never an error in front of the user: every read falls back to the defaults and every write is allowed to
 * fail silently (the setting still applies for this session).
 */

export const PREFS_KEY = "credmgr_prefs";

/** The choices the Settings selects offer; a stored value outside them is ignored. */
export const AUTO_LOCK_CHOICES = [5, 15, 60, 0] as const;
export const REVEAL_CHOICES = [10, 20, 60] as const;
export const RETAIN_CHOICES = [14, 30] as const;

export interface Prefs {
  /** `null` follows the operating system. */
  theme: "dark" | "light" | null;
  colour: "off" | "on" | "auto";
  hue: number;
  intensity: number;
  greyscale: boolean;
  /** `null` follows `prefers-contrast`. */
  contrastMode: "standard" | "high" | null;
  /** `system` follows the operating system's reduced-motion setting (the stylesheet honours it); `reduced` is always on. */
  motion: "system" | "reduced";
  hwAccel: boolean;
  /**
   * Hide the window from screen capture and screen sharing (threat T10).  `true` is the default and the window is created that
   * way; the page calls the shell only when this is stored as `false`, so a missing or unreadable value stays protected.
   */
  captureProtection: boolean;
  mode: "lite" | "pro";
  /** 0 turns the idle timer off (the broker still locks on its own). */
  autoLockMins: number;
  revealWindowSecs: number;
  /** Backups kept by `maintenance.backup`. */
  backupRetain: 14 | 30;
  entriesMode: "all" | "selected";
  view: "graph" | "tree";
}

export type PrefKey = keyof Prefs;
export const PREF_KEYS: readonly PrefKey[] = ["theme", "colour", "hue", "intensity", "greyscale", "contrastMode", "motion", "hwAccel", "captureProtection", "mode", "autoLockMins", "revealWindowSecs", "backupRetain", "entriesMode", "view"];

/** The values the design shipped with. */
export function defaultPrefs(): Prefs {
  return {
    theme: null,
    colour: "off",
    hue: 198,
    intensity: 32,
    greyscale: false,
    contrastMode: null,
    motion: "system",
    hwAccel: true,
    captureProtection: true,
    mode: "pro",
    autoLockMins: 15,
    revealWindowSecs: 20,
    backupRetain: 14,
    entriesMode: "all",
    view: "graph",
  };
}

type Dict = Record<string, unknown>;
const isDict = (v: unknown): v is Dict => typeof v === "object" && v !== null && !Array.isArray(v);
const oneOf = <T>(v: unknown, set: readonly T[]): v is T => set.includes(v as T);

/** The valid fields of `raw`, and only those.  Unknown keys, wrong types and out-of-range numbers are dropped. */
export function pick(raw: unknown): Partial<Prefs> {
  const out: Partial<Prefs> = {};
  if (!isDict(raw)) return out;
  if (oneOf(raw.theme, ["dark", "light", null] as const)) out.theme = raw.theme;
  if (oneOf(raw.colour, ["off", "on", "auto"] as const)) out.colour = raw.colour;
  if (typeof raw.hue === "number" && Number.isFinite(raw.hue) && raw.hue >= 0 && raw.hue <= 360) out.hue = Math.round(raw.hue);
  if (typeof raw.intensity === "number" && Number.isFinite(raw.intensity) && raw.intensity >= 0 && raw.intensity <= 100) out.intensity = Math.round(raw.intensity);
  if (typeof raw.greyscale === "boolean") out.greyscale = raw.greyscale;
  if (oneOf(raw.contrastMode, ["standard", "high", null] as const)) out.contrastMode = raw.contrastMode;
  if (oneOf(raw.motion, ["system", "reduced"] as const)) out.motion = raw.motion;
  if (typeof raw.hwAccel === "boolean") out.hwAccel = raw.hwAccel;
  if (typeof raw.captureProtection === "boolean") out.captureProtection = raw.captureProtection;
  if (oneOf(raw.mode, ["lite", "pro"] as const)) out.mode = raw.mode;
  if (oneOf(raw.autoLockMins, AUTO_LOCK_CHOICES)) out.autoLockMins = raw.autoLockMins;
  if (oneOf(raw.revealWindowSecs, REVEAL_CHOICES)) out.revealWindowSecs = raw.revealWindowSecs;
  if (oneOf(raw.backupRetain, RETAIN_CHOICES)) out.backupRetain = raw.backupRetain;
  if (oneOf(raw.entriesMode, ["all", "selected"] as const)) out.entriesMode = raw.entriesMode;
  if (oneOf(raw.view, ["graph", "tree"] as const)) out.view = raw.view;
  return out;
}

/** The webview's storage, or `null` when it cannot be reached (blocked, or there is no window at all). */
function defaultStorage(): Storage | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
}

function readRaw(storage: Storage | null): unknown {
  if (!storage) return null;
  try {
    const text = storage.getItem(PREFS_KEY);
    return text ? JSON.parse(text) : null;
  } catch {
    return null;
  }
}

/** Only the fields that were stored (and are valid), so the caller can tell "the user chose this" from "the default". */
export function storedPrefs(storage: Storage | null = defaultStorage()): Partial<Prefs> {
  return pick(readRaw(storage));
}

/** Everything, with the defaults filling in what was never chosen. */
export function loadPrefs(storage: Storage | null = defaultStorage()): Prefs {
  return { ...defaultPrefs(), ...storedPrefs(storage) };
}

/**
 * Remember `patch` on top of what is already stored, and return the result.  Invalid fields are dropped, not stored.
 * Never throws: when storage refuses, the returned prefs still reflect the patch.
 */
export function savePrefs(patch: Partial<Prefs>, storage: Storage | null = defaultStorage()): Prefs {
  const next = { ...storedPrefs(storage), ...pick(patch) };
  if (storage) {
    try {
      storage.setItem(PREFS_KEY, JSON.stringify(next));
    } catch {
      /* not remembered; the setting still applies for this session */
    }
  }
  return { ...defaultPrefs(), ...next };
}
