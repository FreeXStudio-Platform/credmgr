/**
 * `VaultModel`: the one place the screens' data comes from (spec B1; the interface is FROZEN for the wiring packages).
 *
 * The logic class reads `this.vault` synchronously on every render.  `this.vault` is `model.view`, a plain object this
 * class REPLACES (never edits) when it refreshes.  Reads are free; anything that changes the vault goes
 * `await action()` → `model.refresh({...affected})` → flash, or `routeError(e, ctx)` on failure.  There are no optimistic
 * writes: what the screen shows is what the broker last said.
 *
 * Plaintext (a revealed value, a TOTP code) never enters `view`.  It lives in this class's private store, is handed out
 * by {@link VaultModel.plain}, expires on its own, and is wiped on lock and when the window is hidden.
 *
 * What a wiring package changes: the `ModelSource` it reads through, and the action modules (actions/*.ts) that call
 * the bridge and then `refresh()`.  What it does NOT change: who calls the model (the logic class), or these signatures.
 */
import { errorCode, isSessionEnded } from "./errors";
import type { LockResult } from "./source";
import type { AuthLite, ModelSource } from "./source";
import { emptyView, type DEntry, type DEntryDetail, type DNode, type DPending, type DSealed, type DView, type ModelStatus, type RefreshSpec, type UnreadableCode } from "./types";

export interface ModelOptions {
  /** Read every node's note while loading (the demo shows all of them at once; the real app reads one on select). */
  eagerNotes?: boolean;
  /** Fetch the value of every field that is not masked while loading, so it can be shown without a click. */
  prefetchUnmasked?: boolean;
  /** Re-read everything after an unlock.  The demo keeps its in-memory edits instead. */
  reloadOnUnlock?: boolean;
  /** Empty the view on lock.  The demo keeps it. */
  clearViewOnLock?: boolean;
  /** Deep-freeze every view, so a screen that mutates it throws.  `createModel()` switches it on for every model that talks to the broker, in every build. */
  freezeView?: boolean;
  /** How long a revealed value stays readable when the caller does not say (ms). */
  revealWindowMs?: number;
  /**
   * Called when `lock()` ended locally but the broker did not confirm that the vault locked (it was unreachable, or it
   * answered with an error).  The logic raises a notice; the model has no UI.  `code` is the error's code, never its message.
   */
  onLockUnconfirmed?: (code: string | null) => void;
  /** Clock, for tests. */
  now?: () => number;
}

type Listener = () => void;

interface Secret {
  value: string;
  until: number;
}

/** What a caller that is WAITING on a read (the unlock that was loading the vault) is refused with when its login ended meanwhile. */
const sessionEnded = (): { source: "bridge"; code: string; message: string } => ({
  source: "bridge",
  code: "session_expired",
  message: "the login ended while the vault was being read",
});

const FIELD_SEP = "\u0000";
/** A field is named by its id (`f_...`, from the broker), or by its position in an entry that has no ids (the example data). */
export type FieldKey = number | string;
const keyOf = (node: string, entry: string, field: FieldKey): string => `${node}${FIELD_SEP}${entry}${FIELD_SEP}${field}`;
const entryPrefix = (node: string, entry: string): string => `${node}${FIELD_SEP}${entry}${FIELD_SEP}`;
const detailKey = (node: string, entry: string): string => `${node}${FIELD_SEP}${entry}`;
/** The key an entry's fields are held under: the field's id when it has one, else its position. */
export const fieldKeyOf = (f: { id?: string }, index: number): FieldKey => f.id ?? index;

/** Run `fn` over `items`, at most `limit` at a time, keeping the order of the results. */
export async function mapPool<T, R>(items: readonly T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

export function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const v of Object.values(value as Record<string, unknown>)) deepFreeze(v);
  }
  return value;
}

export class VaultModel {
  /** The broker's last word: replaced wholesale on refresh, never edited.  Deep-frozen when `freezeView` is on (always, for a model that reads from the broker). */
  view: DView = emptyView();
  /** The manifest generation `entry.list` last returned, per node.  Echo it on every mutation of an entry. */
  generation: Record<string, number> = {};
  /** The registry's `kind: "orphan"` node.  It is kept out of `view.nodes`; `view.orphans` holds its items. */
  orphanNodeId: string | null = null;
  status: ModelStatus = "starting";
  /** How many agent requests were waiting for a person when the last `boot()` asked (ADR-090). A hint for the Lock screen's first look, never a view of them. */
  pendingApprovals = 0;
  /** True iff the last login went through the second-factor step (a confirmed gate always makes unlock ask for it). */
  gateConfirmed = false;

  readonly source: ModelSource;
  readonly options: Required<Omit<ModelOptions, "now">> & { now: () => number };

  readonly #listeners = new Set<Listener>();
  /** Values the user asked to see.  They expire and are wiped on lock and on window hide. */
  readonly #secret = new Map<string, Secret>();
  /** Values of fields the model was told are not secret (`prefetchUnmasked`).  Wiped on lock only. */
  readonly #shown = new Map<string, string>();
  /**
   * Bumped by every `clear()`.  A read that began in an earlier epoch outlived its login: it publishes nothing and stores
   * nothing, because whatever it returns would otherwise land in a model that has just been emptied.
   */
  #epoch = 0;
  /** The reveal each key is waiting on.  `hide()`, `wipeSecrets()` and `clear()` cancel it, so a late answer cannot bring a value back. */
  readonly #revealing = new Map<string, number>();
  #revealSeq = 0;
  /**
   * What `entry.get` said about the entries the user opened: field ids, labels, types, masking, never a value.  The labels are the user's
   * own text, so they are dropped with everything else on lock.  A detail is replaced whole, never edited.
   */
  readonly #details = new Map<string, DEntryDetail>();
  /** Bumped every time the held values are wiped (window hidden, node changed, entry closed, lock), so a screen can tell "my value was dropped" from "I never asked". */
  #wipes = 0;
  /** The tail of the reads that publish a view.  They run one at a time, each starting from the view the one before it left. */
  #queue: Promise<unknown> = Promise.resolve();

  constructor(source: ModelSource, options: ModelOptions = {}) {
    this.source = source;
    this.options = {
      eagerNotes: options.eagerNotes ?? false,
      prefetchUnmasked: options.prefetchUnmasked ?? false,
      reloadOnUnlock: options.reloadOnUnlock ?? true,
      clearViewOnLock: options.clearViewOnLock ?? true,
      freezeView: options.freezeView ?? false,
      revealWindowMs: options.revealWindowMs ?? 20_000,
      onLockUnconfirmed: options.onLockUnconfirmed ?? (() => {}),
      now: options.now ?? Date.now,
    };
  }

  /** `"demo"` only in a development or test build that runs without the Tauri shell (the in-memory example vault).  Every release build is `"bridge"`. */
  get kind(): "bridge" | "demo" {
    return this.source.kind;
  }

  // ─────────────────────────────── subscriptions ───────────────────────────────

  /** `fn` runs after every change to `status` or `view`.  Returns the unsubscribe function. */
  subscribe(fn: Listener): () => void {
    this.#listeners.add(fn);
    return () => {
      this.#listeners.delete(fn);
    };
  }

  #emit(): void {
    for (const fn of [...this.#listeners]) fn();
  }

  #setView(view: DView): void {
    this.view = this.options.freezeView ? deepFreeze(view) : view;
  }

  // ─────────────────────────────── session ───────────────────────────────

  /**
   * Ask the broker where things stand and route: no vault yet → `uninitialized`; locked, or unlocked by another process
   * (so this one holds no login) → `locked`; open → load everything → `unlocked`.  An unreachable broker is a state
   * (`broker-down`), not an exception.  Any other failure is thrown for the caller to route.  Every state except `unlocked`
   * goes through {@link clear}: a Lock screen reached from here (Retry after a broker-down screen, a vault another process
   * locked) shows nothing the previous session held, and no value revealed in it can be copied after the next login.
   */
  async boot(): Promise<void> {
    this.status = "starting";
    this.#emit();
    let auth: AuthLite;
    try {
      auth = await this.source.status();
    } catch (e) {
      if (errorCode(e) === "broker_unreachable") {
        this.clear("broker-down"); // a restarted broker has forgotten every login: nothing of the last session may outlive it
        return;
      }
      throw e;
    }
    // Every answer that is not "open" ends whatever login the model held: the view, the notes and every revealed value go,
    // not just the status.  (boot() runs again from Retry and from a screen that lost the broker; the model it finds may still
    // hold the session that was just lost.)
    this.pendingApprovals = auth.pendingApprovals ?? 0;
    if (!auth.initialized) this.clear("uninitialized");
    else if (auth.locked || !auth.authenticated) this.clear("locked");
    else {
      try {
        // `false`: the login ended while the vault was being read, `clear()` already said so, and nothing was published.
        if (await this.#serial(() => this.#loadAll())) this.status = "unlocked";
      } catch (e) {
        if (!isSessionEnded(e)) throw e;
        this.status = "locked";
      }
    }
    this.#emit();
  }

  /**
   * Passphrase step.  Resolves when the vault is open and loaded.  Rejects with the bridge's error: notably
   * `two_factor_required` (then {@link gateVerify}), `wrong_passphrase` and `rate_limited`.
   */
  async unlock(passphrase: string): Promise<void> {
    try {
      await this.source.unlock(passphrase);
    } catch (e) {
      if (errorCode(e) === "two_factor_required") this.gateConfirmed = true;
      throw e;
    }
    this.gateConfirmed = false;
    await this.#opened();
  }

  /** Second-factor step after `two_factor_required`.  Resolves when the vault is open and loaded. */
  async gateVerify(code: string): Promise<void> {
    await this.source.gateVerify(code);
    this.gateConfirmed = true;
    await this.#opened();
  }

  async #opened(): Promise<void> {
    if (this.options.reloadOnUnlock || this.view.nodes.length === 0) {
      // A login that ended while its vault was loading is not an unlock: the caller is told, and must not show the app.
      if (!(await this.#serial(() => this.#loadAll()))) throw sessionEnded();
    }
    this.status = "unlocked";
    this.#emit();
  }

  /**
   * Lock: forget everything the session held AT ONCE, and tell the broker meanwhile (the bridge drops its token regardless).
   * The screen must not keep showing the vault for as long as the broker takes to answer (a wedged broker is the shell's 30 s
   * read timeout), so nothing here waits on it before {@link clear}.  The app ends locked whatever the broker says; when it
   * could not confirm that the vault locked, that is reported (the result, and `onLockUnconfirmed`) instead of swallowed,
   * because a Lock screen over a vault the broker still holds open is a claim the user would otherwise believe.
   */
  async lock(): Promise<LockResult> {
    const unconfirmed = (e: unknown): LockResult => ({ confirmed: false, code: errorCode(e) ?? "unknown" }); // a source is not meant to throw here; the app still ends locked
    let asked: Promise<LockResult>;
    try {
      asked = Promise.resolve(this.source.lock()).then((r) => r ?? { confirmed: true, code: null }, unconfirmed);
    } catch (e) {
      asked = Promise.resolve(unconfirmed(e));
    }
    this.clear();
    const result = await asked;
    if (!result.confirmed) this.options.onLockUnconfirmed(result.code);
    return result;
  }

  /**
   * Forget what the session held: names, notes, counts, the tray, every revealed value.  Used on every path to locked.
   * `"broker-down"` is the same wipe for the one other way a login ends: the broker went away (a restarted broker has
   * forgotten every login, so nothing on screen may outlive it).
   */
  clear(status: "locked" | "broker-down" | "uninitialized" = "locked"): void {
    this.#secret.clear();
    this.#shown.clear();
    this.#details.clear(); // field labels are the user's own text: they go with the values
    this.#wipes++;
    this.#epoch++; // every read still in flight belongs to the login that just ended
    this.#revealing.clear();
    if (this.options.clearViewOnLock) {
      this.#setView(emptyView());
      this.generation = {};
      this.orphanNodeId = null;
    }
    this.status = status;
    this.#emit();
  }

  /**
   * Liveness: ask the broker whether this process is still logged in.  There is no push channel (bridge.ts rule 4), so the
   * logic calls this every 30 s and when the window comes back, and a broker-side idle lock, a lock from the CLI or a restarted
   * broker is noticed here.  Does nothing unless the model believes it is open.  A lost login or an unreachable broker clears the
   * model and publishes the new status; any other failure is thrown for the caller to route.
   */
  async checkSession(): Promise<void> {
    if (this.status !== "unlocked") return;
    let auth: AuthLite;
    try {
      auth = await this.source.status();
    } catch (e) {
      if (errorCode(e) === "broker_unreachable") {
        if (this.status === "unlocked") this.clear("broker-down");
        return;
      }
      throw e;
    }
    if (this.status !== "unlocked") return; // the user locked, or another call noticed, while this one was in flight
    if (auth.locked || !auth.authenticated) this.clear();
  }

  // ─────────────────────────────── reads ───────────────────────────────

  /**
   * Run `fn` after every read queued before it has finished.  Reads that publish a view each start from the view the one
   * before left, so two of them in flight cannot overwrite each other (a lost update), and the one that was asked second
   * cannot be undone by the one that happened to answer last.
   */
  #serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(fn);
    this.#queue = run.catch(() => undefined); // one failed read must not wedge the queue
    return run;
  }

  /**
   * Read the graph, grants, every node's entries and tray (four at a time), and the orphaned items, then publish one new
   * view.  A read that outlives its login (the vault was locked, or the broker went away, while it was running) publishes
   * nothing and resolves quietly: whoever ended the login has already told the user.
   */
  loadAll(): Promise<void> {
    return this.#serial(() => this.#loadAll()).then(() => undefined);
  }

  /** @returns `false` when the login ended while reading, so nothing was published. */
  async #loadAll(): Promise<boolean> {
    const epoch = this.#epoch;
    const [graph, grants] = await Promise.all([this.source.graph(), this.source.grants()]);
    const ids = graph.nodes.map((n) => n.id);
    const entries: Record<string, DEntry[]> = {};
    const generation: Record<string, number> = {};
    const unreadable: Record<string, UnreadableCode> = {};
    await mapPool(ids, 4, async (id) => {
      const part = await this.source.entries(id);
      entries[id] = part.entries;
      generation[id] = part.generation;
      if (part.unreadable) unreadable[id] = part.unreadable;
    });
    const [orphans, pending] = await Promise.all([this.source.orphans(), mapPool(ids, 4, (id) => this.source.pending(id))]);
    const orphanReason = this.source.orphansUnreadable?.() ?? null;
    if (orphanReason && graph.orphanNodeId) unreadable[graph.orphanNodeId] = orphanReason;
    let nodes = graph.nodes;
    if (this.options.eagerNotes) {
      const notes = await mapPool(ids, 4, (id) => this.source.notes(id));
      nodes = nodes.map((n, i) => ({ ...n, notes: notes[i] }));
    }
    if (epoch !== this.#epoch) return false;
    this.orphanNodeId = graph.orphanNodeId;
    this.generation = generation;
    this.#setView({
      nodes,
      links: [...graph.links, ...grants.map((g) => ({ source: g.from, target: g.to, kind: "grant" as const }))],
      grants,
      entries,
      unreadable,
      orphans,
      sealed: graph.sealed ?? this.view.sealed, // the broker's list is the truth when it gave one (it survives a lock and a restart)
      pending: pending.flat(),
    });
    if (this.options.prefetchUnmasked) await this.#prefetchUnmasked(epoch);
    if (epoch !== this.#epoch) return false;
    this.#emit();
    return true;
  }

  async #prefetchUnmasked(epoch: number): Promise<void> {
    const jobs: Array<[string, string, FieldKey]> = [];
    for (const [node, list] of Object.entries(this.view.entries)) {
      for (const en of list) en.fields.forEach((f, i) => f.masked || jobs.push([node, en.id, fieldKeyOf(f, i)]));
    }
    await mapPool(jobs, 4, async ([node, entry, field]) => {
      const value = await this.source.reveal(node, entry, field);
      if (epoch === this.#epoch) this.#shown.set(keyOf(node, entry, field), value);
    });
  }

  /**
   * Re-read only what a mutation touched, then publish a new view.  An empty spec reads nothing and publishes nothing.
   * This is the one signature every wiring package calls after a successful mutation.  Refreshes run one at a time, in
   * the order they were asked; one that outlives its login publishes nothing and resolves quietly (see {@link loadAll}).
   */
  refresh(spec: RefreshSpec): Promise<void> {
    return this.#serial(() => this.#refresh(spec));
  }

  async #refresh(spec: RefreshSpec): Promise<void> {
    const epoch = this.#epoch;
    const v = this.view;
    let nodes: DNode[] = v.nodes;
    let links = v.links;
    let grants = v.grants;
    let orphans = v.orphans;
    let orphanNodeId = this.orphanNodeId;
    const generation = { ...this.generation };
    const entries = { ...v.entries };
    const unreadable: Record<string, UnreadableCode> = { ...v.unreadable };
    let pending: DPending[] = v.pending;
    let sealed: DSealed[] | undefined;
    let touched = false;

    if (spec.graph) {
      const g = await this.source.graph();
      orphanNodeId = g.orphanNodeId;
      sealed = g.sealed;
      const notes = new Map(v.nodes.map((n) => [n.id, n.notes] as const));
      nodes = g.nodes.map((n) => ({ ...n, notes: notes.get(n.id) ?? null }));
      links = [...g.links, ...links.filter((l) => l.kind === "grant")];
      orphans = await this.source.orphans();
      const orphanReason = this.source.orphansUnreadable?.() ?? null;
      if (orphanNodeId) {
        if (orphanReason) unreadable[orphanNodeId] = orphanReason;
        else delete unreadable[orphanNodeId];
      }
      // Entry lists (and unreadable marks) of nodes that no longer exist go too.
      const keep = new Set(nodes.map((n) => n.id));
      if (orphanNodeId) keep.add(orphanNodeId);
      for (const id of Object.keys(entries)) if (!keep.has(id)) delete entries[id];
      for (const id of Object.keys(unreadable)) if (!keep.has(id)) delete unreadable[id];
      touched = true;
    }
    if (spec.grants) {
      grants = await this.source.grants();
      links = [...links.filter((l) => l.kind === "structural"), ...grants.map((g) => ({ source: g.from, target: g.to, kind: "grant" as const }))];
      touched = true;
    }
    if (spec.nodes?.length) {
      const ids = [...new Set(spec.nodes)];
      await mapPool(ids, 4, async (id) => {
        const part = await this.source.entries(id);
        entries[id] = part.entries;
        generation[id] = part.generation;
        if (part.unreadable) unreadable[id] = part.unreadable;
        else delete unreadable[id];
      });
      touched = true;
    }
    if (spec.pending) {
      pending = (await mapPool(nodes.map((n) => n.id), 4, (id) => this.source.pending(id))).flat();
      touched = true;
    }
    if (spec.notes !== undefined) {
      const text = await this.source.notes(spec.notes);
      nodes = nodes.map((n) => (n.id === spec.notes ? { ...n, notes: text } : n));
      touched = true;
    }
    // Entry details are not part of the view (they hold labels, and are replaced one by one), so they are read here and put in the
    // model's own map once the login is known to have survived.
    const details: Array<[string, DEntryDetail | null]> = [];
    if (spec.details?.length && this.source.entryMeta) {
      const meta = this.source.entryMeta.bind(this.source);
      const seen = new Set<string>();
      const wanted = spec.details.filter((d) => !seen.has(detailKey(d.node, d.entry)) && seen.add(detailKey(d.node, d.entry)));
      await mapPool(wanted, 4, async (d) => {
        try {
          details.push([detailKey(d.node, d.entry), await meta(d.node, d.entry)]);
        } catch (e) {
          // The entry is gone, or its node was locked meanwhile: there is nothing to show of its fields now.  Anything else is the caller's.
          const c = errorCode(e);
          if (c !== "not_found" && c !== "node_locked" && c !== "node_access_denied") throw e;
          details.push([detailKey(d.node, d.entry), null]);
        }
      });
      touched = true;
    }
    if (epoch !== this.#epoch) return; // the login ended while this was reading: publish nothing, and keep nothing it learned
    for (const [k, d] of details) {
      if (d) this.#details.set(k, this.options.freezeView ? deepFreeze(d) : d);
      else this.#details.delete(k);
    }
    this.orphanNodeId = orphanNodeId; // (unchanged values when nothing was touched)
    this.generation = generation;
    if (!touched) return;
    this.#setView({ nodes, links, grants, entries, unreadable, orphans, sealed: sealed ?? this.view.sealed, pending }); // not `v.sealed`: a seal recorded while this refresh was reading must survive it, unless the broker listed the seals
    this.#emit();
  }

  /**
   * Run a mutation and then refresh what it touched.  The mutation's own rejection propagates untouched (the caller
   * sends it to `routeError`); a refresh failure after a SUCCESSFUL mutation also propagates, because the screen would
   * otherwise show data the broker has already changed.
   */
  async mutate<T>(action: () => Promise<T>, affected: RefreshSpec): Promise<T> {
    const result = await action();
    await this.refresh(affected);
    return result;
  }

  // ─────────────────────────────── sealed nodes (session memory, gap G4) ───────────────────────────────

  /**
   * What "Restore" in Settings reads is `view.sealed`.  When the source lists the sealed nodes (the bridge: `meta.sealed`, ADR-080) every
   * graph read replaces it with that list, so it survives a lock and a daemon restart; this method only bridges the instant between a
   * seal and the re-read, and serves sources that cannot list (the example vault, an agent login).
   */
  rememberSealed(item: DSealed): void {
    this.#setView({ ...this.view, sealed: [...this.view.sealed.filter((s) => s.id !== item.id), item] });
    this.#emit();
  }

  /** Forget a remembered sealed node (it was restored, or its 7-day window is over). */
  forgetSealed(id: string): void {
    if (!this.view.sealed.some((s) => s.id === id)) return;
    this.#setView({ ...this.view, sealed: this.view.sealed.filter((s) => s.id !== id) });
    this.#emit();
  }

  // ─────────────────────────────── view helpers ───────────────────────────────

  node(id: string): DNode | undefined {
    return this.view.nodes.find((n) => n.id === id);
  }

  children(id: string): DNode[] {
    return this.view.nodes.filter((n) => n.parentId === id);
  }

  entriesOf(node: string): DEntry[] {
    return this.view.entries[node] ?? [];
  }

  // ─────────────────────────────── entry details (ADR-078) ───────────────────────────────

  /**
   * What the broker last said about an entry's fields (ids, labels, types, masking; never a value), or `undefined` until it has been
   * read.  A bridge entry's list row carries no fields, so the entry detail screen draws from this and from nothing else.
   */
  detail(node: string, entry: string): DEntryDetail | undefined {
    return this.#details.get(detailKey(node, entry));
  }

  /**
   * Read an entry's fields (`entry.get`) and keep the answer.  Rejects with the broker's refusal (`node_locked`, `not_found`, ...) for the
   * caller to route.  An answer that outlived its login is dropped and resolves `undefined`: whoever ended the login has said so.
   */
  async loadDetail(node: string, entry: string): Promise<DEntryDetail | undefined> {
    if (!this.source.entryMeta) return undefined;
    const epoch = this.#epoch;
    const d = await this.source.entryMeta(node, entry);
    if (epoch !== this.#epoch) return undefined;
    this.#details.set(detailKey(node, entry), this.options.freezeView ? deepFreeze(d) : d);
    this.#emit();
    return d;
  }

  /** Forget what was read of an entry's fields (the entry was closed, removed, or its node locked). */
  dropDetail(node: string, entry: string): void {
    this.#details.delete(detailKey(node, entry));
  }

  // ─────────────────────────────── plaintext ───────────────────────────────

  /**
   * Fetch one field's value into the private store for `windowMs` (default {@link ModelOptions.revealWindowMs}).
   * `field` is the field's id (`f_...`), or its position for the example data.
   * Resolves `true` when the value is held.  Resolves `false`, holding nothing, when the answer arrived after the user
   * had hidden the field, moved to another node, hidden the window, or locked: a value fetched for a screen that is gone is
   * dropped on arrival, never parked in memory.  (Use the boolean, or `plain()`, before telling the user a value is showing.)
   */
  async reveal(node: string, entry: string, field: FieldKey = 0, windowMs = this.options.revealWindowMs): Promise<boolean> {
    return (await this.holdFetched(node, entry, field, () => this.source.reveal(node, entry, field), (value) => ({ value, windowMs }))).held;
  }

  /**
   * Fetch SEVERAL fields of one entry in one call (one broker read, one audit record) and hold each for `windowMs`.  This is how the
   * fields that are not masked are shown without a click.  Same rules as {@link reveal}: `true` only when every value is held, and an
   * answer that arrives after the screen it was for is gone is dropped on arrival.
   */
  async revealMany(node: string, entry: string, fields: string[], windowMs = this.options.revealWindowMs): Promise<boolean> {
    if (!fields.length) return true;
    const k = keyOf(node, entry, "*");
    const ticket = ++this.#revealSeq;
    this.#revealing.set(k, ticket);
    try {
      const got = this.source.revealFields
        ? await this.source.revealFields(node, entry, fields)
        : await Promise.all(fields.map(async (id) => ({ id, value: await this.source.reveal(node, entry, id) })));
      if (this.#revealing.get(k) !== ticket) return false; // hide-all, wipeSecrets() or clear() got here first
      const until = this.options.now() + windowMs;
      for (const { id, value } of got) this.#secret.set(keyOf(node, entry, id), { value, until });
      return true;
    } finally {
      if (this.#revealing.get(k) === ticket) this.#revealing.delete(k);
    }
  }

  /**
   * The one way a value enters the private store.  `fetch` asks the broker (a reveal, a TOTP code); `take` says which string to
   * keep and for how long.  The request holds a ticket from the moment it starts: {@link hide}, {@link wipeSecrets} (window hidden,
   * node changed) and {@link clear} (lock) cancel it, and a cancelled request's answer is dropped on arrival, held nowhere, while
   * the caller still gets the broker's answer back as `result` (a TOTP code's expiry, say) with `held: false`.  A rejection from
   * `fetch` propagates and leaves nothing.
   */
  async holdFetched<T>(node: string, entry: string, field: FieldKey, fetch: () => Promise<T>, take: (result: T) => { value: string; windowMs: number }): Promise<{ held: boolean; result: T }> {
    const k = keyOf(node, entry, field);
    const ticket = ++this.#revealSeq;
    this.#revealing.set(k, ticket);
    try {
      const result = await fetch();
      if (this.#revealing.get(k) !== ticket) return { held: false, result }; // hide(), wipeSecrets(), clear() or a newer request got here first
      const { value, windowMs } = take(result);
      this.#secret.set(k, { value, until: this.options.now() + windowMs });
      return { held: true, result };
    } finally {
      if (this.#revealing.get(k) === ticket) this.#revealing.delete(k);
    }
  }

  /** The value if it is currently revealed (or was fetched as non-secret), else `undefined`.  Never log what this returns. */
  plain(node: string, entry: string, field: FieldKey = 0): string | undefined {
    const k = keyOf(node, entry, field);
    const shown = this.#shown.get(k);
    if (shown !== undefined) return shown;
    const s = this.#secret.get(k);
    if (!s) return undefined;
    if (s.until <= this.options.now()) {
      this.#secret.delete(k);
      return undefined;
    }
    return s.value;
  }

  hide(node: string, entry: string, field: FieldKey = 0): void {
    const k = keyOf(node, entry, field);
    this.#secret.delete(k);
    this.#revealing.delete(k); // a reveal still waiting on the broker is cancelled too
  }

  /**
   * Drop every value held for ONE entry, and cancel its reveals still waiting on the broker.  A change to an entry's fields calls this:
   * a value held from before the change (a field whose value was just replaced, a field that is gone) must not be shown again.
   */
  dropEntrySecrets(node: string, entry: string): void {
    const prefix = entryPrefix(node, entry);
    for (const k of [...this.#secret.keys()]) if (k.startsWith(prefix)) this.#secret.delete(k);
    for (const k of [...this.#revealing.keys()]) if (k.startsWith(prefix)) this.#revealing.delete(k);
    this.#wipes++;
  }

  /**
   * Keep the values held for ONE entry (or none, `null`) and drop every other, cancelling their reveals still waiting on the broker.
   * This is the model's single "which entry is open" path: the screen calls it with the entry it is showing, so no route that changes
   * the open entry (graph dot, list, search, keyboard) can leave the previous entry's values in memory.  Counts as a wipe only if it
   * dropped something.
   */
  retainSecretsFor(node: string | null, entry: string | null): void {
    const keep = node !== null && entry !== null ? entryPrefix(node, entry) : null;
    let dropped = false;
    for (const k of [...this.#secret.keys()]) if (keep === null || !k.startsWith(keep)) { this.#secret.delete(k); dropped = true; }
    for (const k of [...this.#revealing.keys()]) if (keep === null || !k.startsWith(keep)) { this.#revealing.delete(k); dropped = true; }
    if (dropped) this.#wipes++;
  }

  /** Drop every revealed value (window hidden, node changed).  Non-secret fetched values stay. */
  wipeSecrets(): void {
    this.#secret.clear();
    this.#revealing.clear(); // and cancel the reveals still waiting on the broker
    this.#wipes++;
  }

  /** How many times held values have been wiped (all, or one entry's): a screen that asked for a value compares it with the count it saw. */
  get wipeCount(): number {
    return this.#wipes;
  }

  /** Bumped every time a login ends (`clear()`): what a screen asked of one login it must ask again of the next. */
  get epoch(): number {
    return this.#epoch;
  }

  /** Drop expired values; returns how many were dropped.  The logic's 250 ms timer calls it. */
  sweepSecrets(): number {
    const now = this.options.now();
    let n = 0;
    for (const [k, s] of this.#secret) {
      if (s.until <= now) {
        this.#secret.delete(k);
        n++;
      }
    }
    return n;
  }

  /** How many revealed values are held right now (for tests and for the "wiped on lock" proof; never their content). */
  get secretCount(): number {
    return this.#secret.size;
  }
}
