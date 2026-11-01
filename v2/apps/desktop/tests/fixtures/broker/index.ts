/**
 * The Node side of the fixture broker: install the in-page fake (the *.js files in this directory) into a Playwright page
 * and drive it from a spec.
 *
 *   const broker = await installBroker(page, { locked: true, gate: false });
 *   ...
 *   expect(await broker.calls("vault_unlock")).toEqual([{ cmd: "vault_unlock", args: { passphrase: FIXTURE_PASSPHRASE } }]);
 *   await broker.script("entry_reveal", { error: { code: "capability_not_held" } });   // the next reveal is refused
 *
 * It fakes the layer BELOW src/lib/bridge.ts (`window.__TAURI_INTERNALS__.invoke`), so a spec exercises the real bridge
 * client, the real model and the real screens, and asserts the exact command names and argument keys the bridge sends.
 */
import type { Page } from "@playwright/test";

import { brokerScript } from "./script.mjs";

export { brokerScript };

export { FIXTURE_ENROL_CODE, FIXTURE_GATE_CODE, FIXTURE_INIT_RECOVERY_CODE, FIXTURE_PASSPHRASE, FIXTURE_ROOT_RECOVERY_CODE } from "./script.mjs";

export interface BrokerOptions {
  /** Start locked (default) or already logged in. */
  locked?: boolean;
  /** A second factor is enrolled: unlock answers `two_factor_required` until `vault_gate_verify` gets {@link FIXTURE_GATE_CODE}. */
  gate?: boolean;
  /** `false` is a first run: there is no vault to unlock. */
  initialized?: boolean;
  /** The root recovery code `vault_gate_recover` wants with the passphrase (default {@link FIXTURE_ROOT_RECOVERY_CODE}). */
  rootRecoveryCode?: string;
  /** The code that confirms a gate enrolment (default {@link FIXTURE_ENROL_CODE}). */
  enrollCode?: string;
  /** Every broker call fails with `broker_unreachable` until `set({ unreachable: false })`. */
  unreachable?: boolean;
  passphrase?: string;
  gateCode?: string;
  /** Agent requests already waiting when the vault starts (ADR-090): `{ rq_x: { node, entry, expiresIn? } }`. */
  approvals?: Record<string, { node: string; entry: string; expiresIn?: number }>;
  /** Node ids whose name is private (`privateNames`): `vault_approval_get` withholds their names while the vault is locked. */
  privateNodes?: string[];
}

export interface Call {
  cmd: string;
  args: Record<string, unknown>;
}

/** What a scripted answer can be. */
export type Scripted =
  | { error: { code: string; message?: string; detail?: Record<string, unknown>; source?: "transport" | "protocol" | "broker" | "bridge" } }
  | { result: unknown }
  | { delayMs: number };

/** The fake broker's own state, as far as a spec asserts on it. */
export interface BrokerState {
  locked: boolean;
  authenticated: boolean;
  initialized: boolean;
  gateEnrolled: boolean;
  passphrase: string;
  nodes: Array<{ id: string; gate: { locked: boolean } }>;
  entries: Record<string, Array<{ id: string; name: string; value: string }>>;
  pending: Record<string, Array<{ id: string; name: string }>>;
  audit: Array<{ action: string; node: string | null; entry: string | null; decision: string }>;
  grants: Array<{ id: string }>;
}

export class Broker {
  constructor(private readonly page: Page) {}

  /** The calls the app made, oldest first (all, or only `cmd`).  Arguments are copies. */
  calls(cmd?: string): Promise<Call[]> {
    return this.page.evaluate((c) => (window as any).__BROKER__.calls(c), cmd);
  }

  /** Just the command names, for "this happened, in this order" assertions. */
  async commands(): Promise<string[]> {
    return (await this.calls()).map((c) => c.cmd);
  }

  /** Answer the next calls of `cmd` with these, in order; after that the real fixture handler answers again. */
  script(cmd: string, ...responses: Scripted[]): Promise<void> {
    return this.page.evaluate(([c, r]) => (window as any).__BROKER__.script(c, r), [cmd, responses] as const);
  }

  /** Deliver a shell event to the page's listeners (what the Tauri shell does with `app.emit`).  Resolves to how many listeners ran. */
  emit(event: string, payload?: unknown): Promise<number> {
    return this.page.evaluate(([e, p]) => (window as any).__BROKER__.emit(e, p), [event, payload] as const);
  }

  /** The events the page is listening to right now. */
  listening(): Promise<string[]> {
    return this.page.evaluate(() => (window as any).__BROKER__.listening());
  }

  state(): Promise<BrokerState> {
    return this.page.evaluate(() => (window as any).__BROKER__.state());
  }

  /** Change the fake vault's state without a call, e.g. `{ unreachable: false }`. */
  set(patch: Record<string, unknown>): Promise<void> {
    return this.page.evaluate((p) => (window as any).__BROKER__.set(p), patch);
  }

  reset(options?: BrokerOptions): Promise<void> {
    return this.page.evaluate((o) => (window as any).__BROKER__.reset(o), options);
  }
}

/**
 * Install the fake into `page` before any page script runs.  `addInitScript` runs outside the page's Content-Security-Policy,
 * so installing a fake does not weaken the policy under test.
 */
export async function installBroker(page: Page, options: BrokerOptions = {}): Promise<Broker> {
  await page.addInitScript({ content: brokerScript(options) });
  return new Broker(page);
}
