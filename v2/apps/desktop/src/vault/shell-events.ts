/**
 * What the Tauri shell tells the page on its own initiative (src-tauri/src/autolock.rs and src-tauri/src/shell.rs).
 *
 * `credmgr://locked`: the shell locks the vault itself when the Mac sleeps, the display sleeps, the user session changes or the
 * screen locks.  It calls `vault.lock` Rust-side (so it works even if this webview is wedged), drops the bridge's login, and then
 * emits the event with the reason as a string.  The page's job is only to forget: wipe every name and revealed value and show the
 * Lock screen.  There is nothing to lock again, so no `vault_lock` call follows.
 *
 * `credmgr://window-inactive`: the window stopped being the one the user is looking at (minimised, hidden, or focus moved to
 * another app).  The page wipes what it revealed and nothing else: the vault stays open and the clipboard is left alone (clearing
 * it on an app switch would make pasting into the app you copied for impossible).
 *
 * Only this module touches `@tauri-apps/api/event`, and only inside the Tauri shell.
 */
import { listen } from "@tauri-apps/api/event";

/** The event the shell emits when it has locked the vault.  Held to `SHELL_EVENTS.locked` in src/lib/bridge.ts by tests/unit/shell-events.test.ts. */
export const SHELL_LOCKED_EVENT = "credmgr://locked";

/** Why the shell locked the vault, in words for the Lock screen.  Chosen here by reason; the payload is never shown as is. */
export function shellLockNote(reason: unknown): string {
  switch (reason) {
    case "sleep":
      return "Locked because this Mac went to sleep.";
    case "screens_sleep":
      return "Locked because the display went to sleep.";
    case "session_resign":
      return "Locked because the user session changed.";
    case "screen_locked":
      return "Locked because the screen was locked.";
    case "tray":
      return "Locked from the menu bar.";
    case "window_closed":
      return "Locked because the window was closed.";
    default:
      return "The vault was locked by the system.";
  }
}

/** The `sessionStorage` key the shell leaves the lock reason under before it reloads the page (src-tauri/src/autolock.rs `RELOAD_REASON_KEY`). */
export const RELOAD_REASON_KEY = "cm.lockreason";

const SHELL_REASONS = new Set(["sleep", "screens_sleep", "session_resign", "screen_locked", "tray", "window_closed"]);

/**
 * The Lock screen's note after the shell reloaded the page because it locked the vault (ADR-091): the reason the shell left behind, in
 * the same words the event would have given, or `""` when there is none.  Read once and deleted; only the six fixed words count, so
 * nothing else a page could have stored is ever shown.  Never throws (storage can be unavailable).
 */
export function takeReloadLockNote(): string {
  try {
    const reason = sessionStorage.getItem(RELOAD_REASON_KEY);
    sessionStorage.removeItem(RELOAD_REASON_KEY);
    const own = sessionStorage.getItem(PAGE_LOCK_NOTE_KEY);
    sessionStorage.removeItem(PAGE_LOCK_NOTE_KEY);
    if (reason !== null && SHELL_REASONS.has(reason)) return shellLockNote(reason);
    return own !== null && PAGE_LOCK_NOTE_RE.test(own) ? own : "";
  } catch {
    return "";
  }
}

/** The `sessionStorage` key the page leaves its OWN lock note under before it asks the shell to lock (ADR-091 amendment: the shell then
 *  reloads the page, which would otherwise lose the "Locked after N minutes without activity." and "Locked because the window was hidden." lines). */
export const PAGE_LOCK_NOTE_KEY = "cm.locknote";

/** The only notes the page leaves: its idle-timer sentence and the hidden-window sentence (the two locks the page takes without being
 *  asked). A user's own lock says nothing, so nothing is left for it. */
const PAGE_LOCK_NOTE_RE = /^(?:Locked after \d{1,4} minutes? without activity\.|Locked because the window was hidden\.)$/;

/** Leave the page's own lock note for the next boot (a no-op for anything but the idle-timer and hidden-window sentences). Never throws. */
export function rememberPageLockNote(note: string): void {
  try {
    if (PAGE_LOCK_NOTE_RE.test(note)) sessionStorage.setItem(PAGE_LOCK_NOTE_KEY, note);
    else sessionStorage.removeItem(PAGE_LOCK_NOTE_KEY);
  } catch {
    /* storage unavailable: the Lock screen simply says nothing */
  }
}

/** The event the shell emits when the window stopped being the one in front.  Held to `SHELL_EVENTS.windowInactive` in src/lib/bridge.ts by tests/unit/shell-events.test.ts. */
export const SHELL_WINDOW_INACTIVE_EVENT = "credmgr://window-inactive";

async function subscribe(event: string, handler: (reason: unknown) => void): Promise<() => void> {
  const stop = await listen<unknown>(event, (e) => handler(e.payload));
  return () => {
    void stop();
  };
}

/**
 * Call `handler(reason)` whenever the shell reports it has locked the vault.  Resolves to the function that stops listening;
 * rejects if the shell refuses the subscription (the caller tells the user: the 30 s liveness check still catches the lock).
 */
export function onShellLocked(handler: (reason: unknown) => void): Promise<() => void> {
  return subscribe(SHELL_LOCKED_EVENT, handler);
}

/**
 * Call `handler(reason)` whenever the shell reports that the window went inactive (`minimized`, `hidden` or `blurred`; the page
 * treats all three alike).  Resolves to the function that stops listening; rejects if the shell refuses the subscription.
 */
export function onShellWindowInactive(handler: (reason: unknown) => void): Promise<() => void> {
  return subscribe(SHELL_WINDOW_INACTIVE_EVENT, handler);
}
