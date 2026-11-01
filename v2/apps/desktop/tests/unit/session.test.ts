// Work package A, the parts that need no browser: the local QR code, the first-run and recovery actions (against a mocked bridge),
// the model's liveness check, and the shell's lock event.
import qrcode from "qrcode-generator";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as live from "../../src/lib/bridge";
import * as session from "../../src/vault/actions/session";
import { VaultModel } from "../../src/vault/model";
import { otpSecretOf, pathToMatrix, QUIET_ZONE, qrPath } from "../../src/vault/qr";
import { SHELL_LOCKED_EVENT, shellLockNote } from "../../src/vault/shell-events";
import type { AuthLite, ModelSource } from "../../src/vault/source";

vi.mock("../../src/lib/bridge", async (orig) => ({
  ...(await orig<typeof import("../../src/lib/bridge")>()),
  vaultInitBegin: vi.fn(),
  vaultInitConfirm: vi.fn(),
  vaultGateEnrollBegin: vi.fn(),
  vaultGateEnrollConfirm: vi.fn(),
  vaultGateRecover: vi.fn(),
  nodeCreate: vi.fn(),
}));
const bridge = live as unknown as Record<string, ReturnType<typeof vi.fn>>;
const brokerError = (code: string, detail?: Record<string, unknown>) => ({ source: "broker", code, message: code, ...(detail ? { detail } : {}) });

/** A source that opens on unlock and records what the model asked of it. */
class StubSource implements ModelSource {
  readonly kind = "bridge" as const;
  calls: string[] = [];
  auth: AuthLite = { locked: true, authenticated: false, initialized: true };
  async status(): Promise<AuthLite> {
    this.calls.push("status");
    return { ...this.auth };
  }
  async unlock(p: string): Promise<AuthLite> {
    this.calls.push(`unlock:${p}`);
    this.auth = { locked: false, authenticated: true, initialized: true };
    return { ...this.auth };
  }
  async gateVerify(): Promise<AuthLite> {
    return { ...this.auth };
  }
  async lock(): Promise<void> {
    this.calls.push("lock");
  }
  async graph() {
    return { nodes: [{ id: "global", label: "global", kind: "global" as const, depth: 0, parentId: null, counts: { entries: 0, totp: 0 }, gate: { locked: false, twofa: "none" as const }, health: null, notes: null }], links: [], orphanNodeId: null };
  }
  async grants() {
    return [];
  }
  async entries() {
    return { entries: [], generation: 1 };
  }
  async orphans() {
    return [];
  }
  async pending() {
    return [];
  }
  async notes() {
    return null;
  }
  async reveal() {
    return "";
  }
}

describe("the local QR code", () => {
  const URI = "otpauth://totp/CredMgr:global?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=CredMgr&period=30&digits=6";

  it("draws exactly the matrix the library computes for the text, with the quiet zone around it", () => {
    const p = qrPath(URI);
    const qr = qrcode(0, "M");
    qr.addData(URI, "Byte");
    qr.make();
    const n = qr.getModuleCount();
    expect(p.size).toBe(n + QUIET_ZONE * 2);
    const drawn = pathToMatrix(p);
    expect(drawn.length).toBe(n);
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) expect(drawn[r][c], `module ${r},${c}`).toBe(qr.isDark(r, c));
  });

  it("is a version-6 to -7 code for an authenticator URI, and the path is plain path data (nothing to inject)", () => {
    const p = qrPath(URI);
    expect(p.size - QUIET_ZONE * 2).toBeGreaterThanOrEqual(41);
    expect(p.size - QUIET_ZONE * 2).toBeLessThanOrEqual(45);
    expect(p.d).toMatch(/^(M\d+,\d+h\d+v1h-\d+z)+$/);
  });

  it("has the three finder patterns (7x7 rings in three corners) a scanner looks for", () => {
    const m = pathToMatrix(qrPath(URI));
    const n = m.length;
    const ring = (r0: number, c0: number) => {
      for (let i = 0; i < 7; i++) {
        expect(m[r0][c0 + i]).toBe(true);
        expect(m[r0 + 6][c0 + i]).toBe(true);
        expect(m[r0 + i][c0]).toBe(true);
        expect(m[r0 + i][c0 + 6]).toBe(true);
      }
      expect(m[r0 + 1][c0 + 1]).toBe(false); // the light ring inside the dark one
      expect(m[r0 + 3][c0 + 3]).toBe(true); // the dark centre
    };
    ring(0, 0);
    ring(0, n - 7);
    ring(n - 7, 0);
  });

  it("reads the secret out of the URI and groups it in fours", () => {
    expect(otpSecretOf(URI)).toBe("JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP");
    expect(otpSecretOf("otpauth://totp/x?issuer=y")).toBe("");
  });
});

describe("the shell's lock event", () => {
  it("is credmgr://locked, and each reason has its own words (an unknown one gets a generic line, never its payload)", () => {
    expect(SHELL_LOCKED_EVENT).toBe("credmgr://locked");
    expect(shellLockNote("sleep")).toBe("Locked because this Mac went to sleep.");
    expect(shellLockNote("screens_sleep")).toBe("Locked because the display went to sleep.");
    expect(shellLockNote("session_resign")).toBe("Locked because the user session changed.");
    expect(shellLockNote("screen_locked")).toBe("Locked because the screen was locked.");
    expect(shellLockNote("tray")).toBe("Locked from the menu bar.");
    expect(shellLockNote("window_closed")).toBe("Locked because the window was closed.");
    expect(shellLockNote("<img src=x onerror=alert(1)>")).toBe("The vault was locked by the system.");
    expect(shellLockNote(undefined)).toBe("The vault was locked by the system.");
  });
});

describe("first-run and recovery actions", () => {
  beforeEach(() => {
    for (const fn of Object.values(bridge)) if (typeof fn?.mockReset === "function") fn.mockReset();
  });

  it("beginVault returns the broker's answer (the recovery code) and sends only the passphrase", async () => {
    bridge.vaultInitBegin.mockResolvedValue({ recoveryCode: "CODE-1" });
    await expect(session.beginVault(new VaultModel(new StubSource()), "a long passphrase")).resolves.toEqual({ recoveryCode: "CODE-1" });
    expect(bridge.vaultInitBegin).toHaveBeenCalledWith("a long passphrase");
  });

  it("confirmVault sends the retyped code trimmed, and does NOT log in (that is confirmFirstRun's job)", async () => {
    const src = new StubSource();
    bridge.vaultInitConfirm.mockResolvedValue({ initialized: true });
    await session.confirmVault(new VaultModel(src), "  CODE-1\n");
    expect(bridge.vaultInitConfirm).toHaveBeenCalledWith("CODE-1");
    expect(src.calls.filter((c) => c.startsWith("unlock"))).toEqual([]);
  });

  it("confirmFirstRun writes the vault with the retyped code (trimmed), THEN logs in; a refused code logs nobody in", async () => {
    const src = new StubSource();
    const m = new VaultModel(src);
    const order: string[] = [];
    bridge.vaultInitConfirm.mockImplementation(async (code: string) => {
      order.push(`confirm:${code}`);
      return { initialized: true };
    });
    await expect(session.confirmFirstRun(m, "  CODE-1\n", "pass")).resolves.toEqual({});
    expect(src.calls).toContain("unlock:pass");
    expect(order).toEqual(["confirm:CODE-1"]);
    expect(m.status).toBe("unlocked");

    const src2 = new StubSource();
    bridge.vaultInitConfirm.mockRejectedValue(brokerError("recovery_code_mismatch"));
    await expect(session.confirmFirstRun(new VaultModel(src2), "WRONG", "pass")).rejects.toMatchObject({ code: "recovery_code_mismatch" });
    expect(src2.calls.filter((c) => c.startsWith("unlock"))).toEqual([]);
  });

  it("confirmFirstRun: a login that fails AFTER the vault was written is returned, not thrown (the vault exists; the caller goes on to the Lock screen)", async () => {
    const limited = brokerError("rate_limited", { retryAfterSeconds: 30 });
    const src = new StubSource();
    src.unlock = async () => {
      throw limited;
    };
    bridge.vaultInitConfirm.mockResolvedValue({ initialized: true });
    const m = new VaultModel(src);
    await expect(session.confirmFirstRun(m, "CODE-1", "pass")).resolves.toEqual({ unlockError: limited });
    expect(bridge.vaultInitConfirm).toHaveBeenCalledTimes(1);
    expect(m.status).not.toBe("unlocked");
  });

  it("beginGateEnrolment returns the broker's answer; describeEnrolment turns it into a QR and the grouped secret; confirmGateEnrolment returns the codes once and marks the gate in force", async () => {
    const answer = { otpauthUri: "otpauth://totp/CredMgr:global?secret=JBSWY3DPEHPK3PXP&issuer=CredMgr&period=30&digits=6" };
    bridge.vaultGateEnrollBegin.mockResolvedValue(answer);
    const m = new VaultModel(new StubSource());
    const raw = await session.beginGateEnrolment(m);
    expect(raw).toEqual(answer);
    const g = session.describeEnrolment(raw);
    expect(g.secret).toBe("JBSW Y3DP EHPK 3PXP");
    expect(g.qr.d.length).toBeGreaterThan(100);

    expect(m.gateConfirmed).toBe(false);
    bridge.vaultGateEnrollConfirm.mockResolvedValue({ recoveryCodes: ["A", "B"] });
    await expect(session.confirmGateEnrolment(m, " 123456 ")).resolves.toEqual({ recoveryCodes: ["A", "B"] });
    expect(bridge.vaultGateEnrollConfirm).toHaveBeenCalledWith("123456");
    expect(m.gateConfirmed).toBe(true);
  });

  it("recoverGate only resets the gate (it does not log in); recoverAndUnlock then logs in; a refused pair logs nobody in; a login that fails AFTER the reset is returned, not thrown", async () => {
    const only = new StubSource();
    bridge.vaultGateRecover.mockResolvedValue({ gateReset: true });
    await expect(session.recoverGate(new VaultModel(only), "pass", " ROOT-CODE ")).resolves.toEqual({ gateReset: true });
    expect(bridge.vaultGateRecover).toHaveBeenCalledWith("pass", "ROOT-CODE");
    expect(only.calls.filter((c) => c.startsWith("unlock"))).toEqual([]);

    const src = new StubSource();
    await expect(session.recoverAndUnlock(new VaultModel(src), "pass", " ROOT-CODE ")).resolves.toEqual({ gateReset: true });
    expect(src.calls).toContain("unlock:pass");

    const src2 = new StubSource();
    bridge.vaultGateRecover.mockRejectedValue(brokerError("wrong_passphrase"));
    await expect(session.recoverAndUnlock(new VaultModel(src2), "pass", "bad")).rejects.toMatchObject({ code: "wrong_passphrase" });
    expect(src2.calls.filter((c) => c.startsWith("unlock"))).toEqual([]);

    const limited = brokerError("rate_limited", { retryAfterSeconds: 30 });
    const src3 = new StubSource();
    src3.unlock = async () => {
      throw limited;
    };
    bridge.vaultGateRecover.mockResolvedValue({ gateReset: true });
    await expect(session.recoverAndUnlock(new VaultModel(src3), "pass", "ok")).resolves.toEqual({ gateReset: true, unlockError: limited });
  });

  it("slugOf: lower-case letters, digits and hyphens; never empty; never a reserved id", () => {
    expect(session.slugOf("Shop Front")).toBe("shop-front");
    expect(session.slugOf("  --My  App!! v2 ")).toBe("my-app-v2");
    expect(session.slugOf("日本語")).toBe("project");
    expect(session.slugOf("")).toBe("project");
    expect(session.slugOf("Global")).toBe("global-project");
    expect(session.slugOf("orphan")).toBe("orphan-project");
    expect(session.slugOf("x".repeat(80)).length).toBe(40);
  });

  it("createFirstProjects skips blanks, suffixes a taken id, and on a failure says exactly what was made and stops", async () => {
    const src = new StubSource();
    const m = new VaultModel(src);
    await m.boot();
    await m.unlock("p"); // the view now holds `global`
    const refresh = vi.spyOn(m, "refresh").mockResolvedValue(undefined);
    bridge.nodeCreate.mockResolvedValue({ node: "x", created: true });

    const ok = await session.createFirstProjects(m, ["Alpha", "  ", "Alpha"]);
    expect(ok).toEqual({ created: [0, 2], error: undefined });
    expect(bridge.nodeCreate.mock.calls).toEqual([["alpha", "Alpha", "global"], ["alpha-2", "Alpha", "global"]]);
    expect(refresh).toHaveBeenCalledTimes(1);

    bridge.nodeCreate.mockReset();
    refresh.mockClear();
    bridge.nodeCreate.mockResolvedValueOnce({ node: "a", created: true }).mockRejectedValueOnce(brokerError("node_access_denied"));
    const part = await session.createFirstProjects(m, ["One", "Two", "Three"]);
    expect(part.created).toEqual([0]);
    expect(part.error).toMatchObject({ code: "node_access_denied" });
    expect(bridge.nodeCreate).toHaveBeenCalledTimes(2); // "Three" was never attempted
    expect(refresh).toHaveBeenCalledTimes(1); // what was made is reflected

    bridge.nodeCreate.mockReset();
    refresh.mockClear();
    bridge.nodeCreate.mockRejectedValue(brokerError("node_access_denied"));
    const none = await session.createFirstProjects(m, ["Nope"]);
    expect(none.created).toEqual([]);
    expect(refresh).not.toHaveBeenCalled(); // nothing changed, nothing to re-read
  });
});

describe("the model's liveness check", () => {
  it("does nothing unless the model believes it is open", async () => {
    const src = new StubSource();
    const m = new VaultModel(src);
    await m.checkSession();
    expect(src.calls).toEqual([]);
  });

  it("an open vault stays open", async () => {
    const src = new StubSource();
    const m = new VaultModel(src);
    await m.unlock("p");
    await m.checkSession();
    expect(m.status).toBe("unlocked");
    expect(m.view.nodes.length).toBe(1);
  });

  it("a vault locked elsewhere, or a login this process no longer holds, clears the model and publishes it", async () => {
    for (const auth of [{ locked: true, authenticated: false, initialized: true }, { locked: false, authenticated: false, initialized: true }]) {
      const src = new StubSource();
      const m = new VaultModel(src);
      await m.unlock("p");
      const seen: string[] = [];
      m.subscribe(() => seen.push(m.status));
      src.auth = auth;
      await m.checkSession();
      expect(m.status).toBe("locked");
      expect(m.view.nodes).toEqual([]);
      expect(seen).toEqual(["locked"]);
    }
  });

  it("a broker that went away clears the model too, as its own status", async () => {
    const src = new StubSource();
    const m = new VaultModel(src);
    await m.unlock("p");
    src.status = async () => {
      throw { source: "transport", code: "broker_unreachable", message: "x" };
    };
    await m.checkSession();
    expect(m.status).toBe("broker-down");
    expect(m.view.nodes).toEqual([]);
  });

  it("any other failure is thrown for the caller to route, and the model is left as it was", async () => {
    const src = new StubSource();
    const m = new VaultModel(src);
    await m.unlock("p");
    src.status = async () => {
      throw brokerError("internal");
    };
    await expect(m.checkSession()).rejects.toMatchObject({ code: "internal" });
    expect(m.status).toBe("unlocked");
  });

  it("does not undo a lock the user made while the check was in flight", async () => {
    const src = new StubSource();
    const m = new VaultModel(src);
    await m.unlock("p");
    src.status = async () => {
      await m.lock(); // the user locks while the broker is being asked
      return { locked: false, authenticated: true, initialized: true };
    };
    await m.checkSession();
    expect(m.status).toBe("locked");
  });
});
