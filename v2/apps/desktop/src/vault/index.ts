/**
 * The vault layer's entry point: `createModel()` is what the logic class calls once, in its constructor.
 *
 * Which source answers is decided by two facts: is the Tauri shell there, and is this a build that may carry the demo vault?
 *  - Inside the shell (and in the Playwright specs and the design audit, which fake the shell's `invoke` with the fixture
 *    broker) the model talks to the broker through src/lib/bridge.ts.
 *  - With no shell, a development or test build (`vite dev`, vitest, `--mode test`) falls back to the in-memory demo vault, so a
 *    screen can be worked on with no broker.  A RELEASE build has no demo vault at all, in code or in the bundle
 *    (scripts/dc/verify-build.mjs fails the build if any of it is there): with no shell it answers "broker unreachable".
 */
import * as live from "../lib/bridge";
import { BridgeSource } from "./bridge-source";
import { DemoSource } from "./demo-source";
import { lockUnconfirmedText, type NoticeKind } from "./errors";
import { VaultModel, type ModelOptions } from "./model";
import { NoShellSource } from "./no-shell-source";

export function hasTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/**
 * May the in-memory demo vault exist in this build?  A compile-time constant: in a release build both operands fold (`DEV` is
 * `false`, `MODE` is `"production"`), the `if` below is dead code, and the bundler drops `DemoSource` with it.
 */
const DEMO_ALLOWED: boolean = import.meta.env.DEV || import.meta.env.MODE === "test";

/**
 * Options for the real source.  The view is deep-frozen in EVERY build: it is the broker's last word, replaced wholesale and
 * never edited, so a screen that tries to change it in place throws instead of showing data the broker never saw.  Nothing in
 * the logic does (tests/unit/architecture.test.ts reads every logic file for it, and the e2e suite runs frozen), so the freeze
 * costs nothing in use, and it makes "no code path changes what is on screen without a broker call" a property the runtime
 * enforces rather than a convention a later change could quietly break.
 */
export function bridgeModelOptions(): ModelOptions {
  return { freezeView: true };
}

/**
 * `notify` is the logic class's `this.notify(kind, text)`: the one way the model speaks to the user (today, only to say that a
 * lock was not confirmed by the broker).  The model has no UI of its own and chooses the words by code, here.
 */
export function createModel(notify?: (kind: NoticeKind, text: string) => void): VaultModel {
  const hooks: ModelOptions = {
    onLockUnconfirmed: (code) => {
      // Later than the caller's own screen change (showing the Lock screen resets what is on screen, notices included).
      if (notify) setTimeout(() => notify("warn", lockUnconfirmedText(code)), 0);
    },
  };
  if (hasTauriRuntime()) return new VaultModel(new BridgeSource(live), { ...bridgeModelOptions(), ...hooks });
  if (DEMO_ALLOWED) {
    // Development and test builds only.  The demo shows every note and every non-secret field without a click (as designed) and
    // keeps its data across a lock; nothing writes to it (the writes need a broker, and say so).
    return new VaultModel(new DemoSource(), { eagerNotes: true, prefetchUnmasked: true, reloadOnUnlock: false, clearViewOnLock: false, ...hooks });
  }
  return new VaultModel(new NoShellSource(), { ...bridgeModelOptions(), ...hooks });
}

export { fieldKeyOf, VaultModel } from "./model";
export type { FieldKey, ModelOptions } from "./model";
export type { LockResult } from "./source";
export { BridgeSource } from "./bridge-source";
export { classifyError, errorCode, isSessionEnded, lockUnconfirmedText, NotWiredError, routeError } from "./errors";
export type { ErrorContext, ErrorRoute, NoticeKind, RouteHost } from "./errors";
export { copyEntry, loadEntryDetail, loadNotes, lockNode, readTotp, readTotpSeed, renameNode, revealUnmasked, searchEntries, unlockNode } from "./actions/read";
export type { CopyOutcome, TotpShown } from "./actions/read";
export type { DEntry, DEntryDetail, DField, DGrant, DLink, DNode, DOrphan, DPending, DSealed, DView, ModelStatus, RefreshSpec } from "./types";

// The work packages' action modules and prefs, as namespaces: a screen's logic imports `{ write }` from here (the layering
// test lets the logic import only this file), so adding a function to an action module never touches this index.
export * as admin from "./actions/admin";
export * as read from "./actions/read";
export * as session from "./actions/session";
export * as write from "./actions/write";
export { AUTO_LOCK_CHOICES, defaultPrefs, loadPrefs, PREF_KEYS, PREFS_KEY, RETAIN_CHOICES, REVEAL_CHOICES, savePrefs, storedPrefs } from "./prefs";
export type { PrefKey, Prefs } from "./prefs";
