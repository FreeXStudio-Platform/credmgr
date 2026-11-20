/**
 * The switchboard (ADR-155): the app's preferences live in the broker's signed registry as the settings `app.<key>`, the same
 * registry an agent reads and changes through MCP, so the window and an agent never disagree about what is set.
 *
 *   - After an unlock the page reads `settings.list` and applies every `app.*` value: the broker wins.  The webview's
 *     `credmgr_prefs` stays as the cache the page uses before an unlock (screen-capture protection at boot, the theme of the
 *     Lock screen).
 *   - A change the person makes in the app is also sent to the broker (`settings.set`, the owner's own change: direct).
 *     Best effort: a refusal is said in a notice, the local change still applies.
 *   - An agent's change that makes a setting less strict waits for the owner (`settings.request_list`); the owner approves or
 *     denies it here (`settings.request_decide`).  Approving answers `confirmation_required` first; src/lib/bridge.ts asks the
 *     confirm dialog and retries once, exactly as for a reveal, so nothing here knows about it.
 *
 * One migration rule, so an upgrade does not throw away a choice this Mac made before the broker kept app settings: a value the
 * broker holds at its DEFAULT while this Mac's cache holds an explicit, different choice, and that the broker has never recorded a
 * change for (`settings.get` → `recentChanges` is empty), is sent up instead of being overwritten.  A setting the broker has a
 * history for always wins, default or not, so an agent's (approved) change back to a default is not undone by the window.
 *
 * With no shell (the browser preview, a unit test, the demo vault) every function here resolves `null` and calls nothing.
 */
import * as live from "../../lib/bridge";
import { defaultPrefs, pick, PREF_KEYS, storedPrefs, type PrefKey, type Prefs } from "../prefs";
import { redactTokens } from "./admin";

const inShell = (): boolean => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export const APP_PREFIX = "app.";
/** What the audit record says about a change made in the window. */
export const APP_REASON = "changed in the app";
/** And about a choice this Mac made before the broker kept app settings (the migration rule above). */
export const KEPT_REASON = "kept from this Mac: chosen before the vault kept app settings";

/** `autoLockMins` → `app.autoLockMins`. */
export function settingId(key: PrefKey): string {
  return APP_PREFIX + key;
}

/** `app.autoLockMins` → `autoLockMins`; anything that is not one of the app's preferences → `null`. */
export function prefKeyOf(id: unknown): PrefKey | null {
  if (typeof id !== "string" || !id.startsWith(APP_PREFIX)) return null;
  const k = id.slice(APP_PREFIX.length) as PrefKey;
  return PREF_KEYS.includes(k) ? k : null;
}

/** The broker's `app.*` values and defaults, each one checked by the same rules as the local cache (an invalid value is dropped). */
export interface BrokerPrefs {
  values: Partial<Prefs>;
  defaults: Partial<Prefs>;
}

export function brokerPrefsOf(settings: readonly live.SettingView[] | null | undefined): BrokerPrefs {
  const values: Record<string, unknown> = {};
  const defaults: Record<string, unknown> = {};
  for (const s of Array.isArray(settings) ? settings : []) {
    const k = s ? prefKeyOf(s.id) : null;
    if (!k) continue;
    values[k] = s.value;
    defaults[k] = s.default;
  }
  return { values: pick(values), defaults: pick(defaults) };
}

/**
 * Pure: what to do with what the broker said, against this Mac's cache (`stored`: only the explicit choices).
 *  - `apply`: the broker's values that differ from what the page holds now (the cache over the defaults).
 *  - `ask`: keys where the broker sits at its default and the cache holds a different explicit choice; whether they are sent up
 *    or applied depends on the broker's history for them (see the header).
 */
export function planSync(broker: BrokerPrefs, stored: Partial<Prefs>): { apply: Partial<Prefs>; ask: PrefKey[] } {
  const now: Prefs = { ...defaultPrefs(), ...stored };
  const apply: Record<string, unknown> = {};
  const ask: PrefKey[] = [];
  for (const k of PREF_KEYS) {
    if (!(k in broker.values)) continue;
    const v = broker.values[k];
    if (Object.is(v, now[k])) continue;
    if (k in stored && k in broker.defaults && Object.is(v, broker.defaults[k])) ask.push(k);
    else apply[k] = v;
  }
  return { apply: apply as Partial<Prefs>, ask };
}

export interface SyncResult {
  /** The broker's values to show (they differ from the page's). */
  apply: Partial<Prefs>;
  /** This Mac's earlier choices that were sent up instead (the migration rule). */
  kept: Partial<Prefs>;
}

/**
 * Read the broker's `app.*` settings and decide what the page shows.  `null` with no shell.  A refused or unreadable list rejects
 * (the caller decides whether that is worth a word); a refused `settings.get` or upload for one key only means that key follows
 * the broker.
 */
export async function readAppSettings(stored: Partial<Prefs> = storedPrefs()): Promise<SyncResult | null> {
  if (!inShell()) return null;
  const listed = await live.settingsList();
  const broker = brokerPrefsOf(listed?.settings);
  const { apply, ask } = planSync(broker, stored);
  const out: Record<string, unknown> = { ...apply };
  const kept: Record<string, unknown> = {};
  for (const k of ask) {
    let neverSet = false;
    try {
      const one = await live.settingsGet(settingId(k));
      neverSet = !Array.isArray(one?.recentChanges) || one.recentChanges.length === 0;
    } catch {
      neverSet = false;
    }
    if (neverSet) {
      try {
        const r = await live.settingsSet(settingId(k), stored[k], KEPT_REASON);
        if (r && (r.applied || r.change === "same")) {
          kept[k] = stored[k];
          continue;
        }
      } catch {
        /* not kept: the broker's value applies */
      }
    }
    out[k] = broker.values[k];
  }
  return { apply: out as Partial<Prefs>, kept: kept as Partial<Prefs> };
}

/**
 * Send one preference the person changed in the window.  `null` with no shell, and for a value the cache's rules reject (nothing
 * is sent); a refusal from the broker rejects, so the caller can say it.
 */
export async function pushAppSetting(key: PrefKey, value: unknown): Promise<live.SettingSetResult | null> {
  if (!inShell()) return null;
  const clean = pick({ [key]: value }) as Record<string, unknown>;
  if (!(key in clean)) return null;
  return live.settingsSet(settingId(key), clean[key], APP_REASON);
}

// ─────────────────────────────── agents' requests ───────────────────────────────

/** One waiting request, as the screen shows it: every string cleaned and bounded, the values written out. */
export interface AgentRequest {
  request: string;
  id: string;
  node: string | null;
  from: string;
  to: string;
  reason: string;
  cwd: string | null;
  /** ADR-164: the agent token that asked, as the owner reads it ("agent token “ci” (a_…)"), or null. */
  agentToken: string | null;
  expiresIn: number;
  requestedAt: number;
}

/** A setting's value as text: `null` reads "follow the system", everything else as JSON, bounded. */
export function valueText(v: unknown): string {
  if (v === null || v === undefined) return "null (follow the system)";
  if (typeof v === "string") return redactTokens(v);
  try {
    return redactTokens(JSON.stringify(v));
  } catch {
    return "?";
  }
}

const str = (v: unknown): string => (typeof v === "string" ? redactTokens(v) : "");
/** The broker refuses a reason over 500 characters (ADR-155), so the owner always reads the agent's whole reason before deciding. */
export const REASON_MAX = 500;
const reasonText = (v: unknown): string => (typeof v === "string" ? redactTokens(v, REASON_MAX) : "");
const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) && v > 0 ? v : 0);

/** ADR-164 review P1-2: which agent token asked, in the owner's words; null when none did or the shape is off. */
export function agentTokenWords(t: unknown): string | null {
  const o = t as { id?: unknown; label?: unknown } | null | undefined;
  if (!o || typeof o.id !== "string" || !/^a_[0-9a-f]{16}$/.test(o.id)) return null;
  const label = typeof o.label === "string" ? redactTokens(o.label, 64) : "";
  return `agent token “${label}” (${o.id})`;
}

export function scrubRequest(r: live.SettingRequestView): AgentRequest {
  return {
    request: str(r?.request),
    id: str(r?.id),
    node: typeof r?.node === "string" && r.node ? redactTokens(r.node) : null,
    from: valueText(r?.from),
    to: valueText(r?.to),
    reason: reasonText(r?.reason),
    cwd: typeof r?.cwd === "string" && r.cwd ? redactTokens(r.cwd) : null,
    agentToken: agentTokenWords(r?.agentToken),
    expiresIn: num(r?.expiresIn),
    requestedAt: num(r?.requestedAt),
  };
}

/** The requests waiting for the owner, oldest first.  `null` with no shell; a refusal rejects. */
export async function pendingAgentRequests(): Promise<AgentRequest[] | null> {
  if (!inShell()) return null;
  const r = await live.settingsRequestList();
  return (Array.isArray(r?.requests) ? r.requests : [])
    .filter((x) => x && x.state === "pending" && typeof x.request === "string" && x.request.length > 0)
    .map(scrubRequest)
    .sort((a, b) => a.requestedAt - b.requestedAt);
}

/** Approve or deny one request.  Approving a loosening asks for a confirmation first (the bridge does that); a refusal rejects. */
export async function decideAgentRequest(request: string, approve: boolean): Promise<{ state: string; applied: boolean }> {
  if (!inShell()) throw new Error("deciding needs the CredMgr app");
  const r = await live.settingsRequestDecide(request, approve);
  return { state: typeof r?.state === "string" ? r.state : approve ? "approved" : "denied", applied: r?.applied === true };
}
