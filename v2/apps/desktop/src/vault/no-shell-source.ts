/**
 * `NoShellSource`: what answers when the page runs WITHOUT the Tauri shell in a build that has no demo vault (every release
 * build).  There is no broker to ask and no data to invent, so the one honest answer to every question is "the broker cannot be
 * reached": the model then shows the broker-down screen with Retry, exactly as it does for a broker that is not running.
 *
 * A release build served in a plain browser therefore shows an empty app that says so, never someone's example vault.
 */
import type { AuthLite, EntriesPart, GraphPart, LockResult, ModelSource } from "./source";
import type { DGrant, DOrphan, DPending } from "./types";

const UNREACHABLE = { source: "bridge", code: "broker_unreachable", message: "the CredMgr app is not running here: there is no Tauri shell to reach the broker through" } as const;
const no = (): never => {
  throw UNREACHABLE;
};

export class NoShellSource implements ModelSource {
  readonly kind = "bridge" as const;
  async status(): Promise<AuthLite> {
    return no();
  }
  async unlock(): Promise<AuthLite> {
    return no();
  }
  async gateVerify(): Promise<AuthLite> {
    return no();
  }
  async lock(): Promise<LockResult> {
    return { confirmed: false, code: UNREACHABLE.code };
  }
  async graph(): Promise<GraphPart> {
    return no();
  }
  async grants(): Promise<DGrant[]> {
    return no();
  }
  async entries(): Promise<EntriesPart> {
    return no();
  }
  async orphans(): Promise<DOrphan[]> {
    return no();
  }
  async pending(): Promise<DPending[]> {
    return no();
  }
  async notes(): Promise<string | null> {
    return no();
  }
  async reveal(): Promise<string> {
    return no();
  }
}
