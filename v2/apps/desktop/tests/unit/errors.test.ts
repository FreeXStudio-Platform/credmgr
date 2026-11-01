// Error routing: every broker code has a route, the text shown is chosen by code (never taken from the error), and
// routeError carries each route out on the host exactly once.
import { describe, expect, it } from "vitest";

import { classifyError, errorCode, isSessionEnded, lockNoteFor, NotWiredError, PRESENCE_TEXT, routeError, waitText, type RouteHost } from "../../src/vault/errors";

const err = (code: string, detail?: Record<string, unknown>, message = "m") => ({ source: "broker", code, message, ...(detail ? { detail } : {}) });

function host() {
  const log: Array<[string, ...unknown[]]> = [];
  const h: RouteHost = {
    notify: (k, t) => log.push(["notify", k, t]),
    lock: (c) => log.push(["lock", c]),
    nodeLocked: (n) => log.push(["nodeLocked", n]),
    promptTwoFactor: (c) => log.push(["promptTwoFactor", c]),
    brokerDown: () => log.push(["brokerDown"]),
    inline: (f, m, _c, retry) => log.push(retry ? ["inline", f, m, retry] : ["inline", f, m]),
    refresh: (n) => log.push(["refresh", n]),
    alreadyInitialized: () => log.push(["alreadyInitialized"]),
  };
  return { h, log };
}

describe("classifyError", () => {
  it("sends a lost login to the lock screen and a locked node to the node panel (the two must never be confused)", () => {
    expect(classifyError(err("vault_locked"))).toEqual({ route: "lock", code: "vault_locked" });
    expect(classifyError(err("session_expired"))).toEqual({ route: "lock", code: "session_expired" });
    expect(classifyError(err("node_locked", { node: "atlas" }))).toEqual({ route: "node-locked", node: "atlas" });
    expect(classifyError(err("node_locked"), { node: "beacon" })).toEqual({ route: "node-locked", node: "beacon" });
    expect(isSessionEnded(err("vault_locked"))).toBe(true);
    expect(isSessionEnded(err("node_locked"))).toBe(false);
  });

  it("asks for the second factor, and says honestly that presence is not available", () => {
    expect(classifyError(err("two_factor_required"))).toEqual({ route: "two-factor" });
    expect(classifyError(err("presence_required"), { op: "grant.create" })).toEqual({ route: "presence", op: "grant.create", message: PRESENCE_TEXT });
    expect(PRESENCE_TEXT).toMatch(/cannot attest/);
    expect(PRESENCE_TEXT).toMatch(/Nothing was changed/);
  });

  it("puts input problems next to the input", () => {
    expect(classifyError(err("wrong_passphrase"))).toMatchObject({ route: "inline", field: "passphrase" });
    expect(classifyError(err("gate_verification_failed"))).toMatchObject({ route: "inline", field: "code" });
    expect(classifyError(err("recovery_code_mismatch"))).toMatchObject({ route: "inline", field: "recoveryCode" });
    expect(classifyError(err("entry_exists"))).toMatchObject({ route: "inline", field: "name" });
    expect(classifyError(err("wrong_passphrase"), { field: "backupPassphrase" })).toMatchObject({ field: "backupPassphrase" });
  });

  it("shows the retry time and the broker's own rule, but only as bounded plain strings and numbers", () => {
    expect(classifyError(err("rate_limited", { retryAfterSeconds: 29.2 }))).toMatchObject({ message: "Too many attempts. Try again in 30 s." });
    expect(classifyError(err("rate_limited", { retryAfterSeconds: "soon" }))).toMatchObject({ message: "Too many attempts. Try again shortly." });
    expect(classifyError(err("capability_not_held", { rule: "reveal needs a grant" }))).toMatchObject({ message: "Not permitted (reveal needs a grant)." });
    expect(classifyError(err("node_access_denied", { rule: { not: "a string" } }))).toMatchObject({ message: "Not permitted." });
    expect(classifyError(err("node_access_denied", { rule: "x".repeat(500) }))).toMatchObject({ message: "Not permitted." });
  });

  it("a failure AFTER a successful write never says 'Nothing was changed': it says what was saved and that only the screen is stale", () => {
    // the plain case, and a caller that names what was saved
    expect(classifyError(err("internal"), { changed: true })).toEqual({ route: "notice", kind: "error", message: "The change itself was saved. The screen could not be refreshed (internal); reload to see it." });
    expect(classifyError(err("internal"), { changed: "Saved 1 entry to atlas." })).toEqual({ route: "notice", kind: "error", message: "Saved 1 entry to atlas. The screen could not be refreshed (internal); reload to see it." });
    // a programming error in the re-read gets the same honesty (its message is still never shown)
    const r = classifyError(new TypeError("SECRET-IN-MESSAGE"), { changed: "Saved 1 entry to atlas." });
    expect(r).toMatchObject({ route: "notice", kind: "error", message: "Saved 1 entry to atlas. The screen could not be refreshed; reload to see it." });
    expect(JSON.stringify(r)).not.toContain("SECRET-IN-MESSAGE");
    // without the flag nothing changes: a refused call did change nothing
    expect(classifyError(err("internal"))).toMatchObject({ message: "Unexpected error (internal). Nothing was changed." });
    expect(classifyError(new TypeError("x"))).toMatchObject({ message: "Unexpected error. Nothing was changed." });
    // and a lost login after the write still goes to the Lock screen, whatever was saved
    expect(classifyError(err("vault_locked"), { changed: "Saved." })).toEqual({ route: "lock", code: "vault_locked" });
  });

  it("reloads what changed underneath the user", () => {
    expect(classifyError(err("conflict"), { node: "atlas" })).toMatchObject({ route: "refresh", nodes: ["atlas"] });
    for (const c of ["not_found", "archive_expired", "entry_removal_expired", "not_undoable"]) expect(classifyError(err(c), { node: "n" })).toMatchObject({ route: "refresh", nodes: ["n"] });
    expect(classifyError(err("conflict"))).toMatchObject({ route: "refresh", nodes: [] });
  });

  it("first-run codes, and an unreachable broker", () => {
    expect(classifyError(err("vault_already_initialized"))).toMatchObject({ route: "already-initialized" });
    expect(classifyError(err("vault_init_not_pending"))).toMatchObject({ route: "inline", field: null });
    expect(classifyError(err("vault_inside_git_working_tree"))).toMatchObject({ route: "inline", field: null });
    expect(classifyError({ source: "transport", code: "broker_unreachable", message: "x" })).toEqual({ route: "broker-down" });
  });

  it("the shell's clipboard codes are worded, and say nothing of the vault or the value", () => {
    for (const c of ["clipboard_failed", "text_too_large"]) {
      const r = classifyError(err(c, undefined, "RAW-SHELL-TEXT-77"));
      expect(r, c).toMatchObject({ route: "notice", kind: "error" });
      expect(JSON.stringify(r), c).not.toContain("RAW-SHELL-TEXT-77");
      expect(JSON.stringify(r), c).not.toContain("Unexpected");
    }
    expect(classifyError(err("clipboard_failed"))).toMatchObject({ message: "The clipboard could not be written. Nothing was copied." });
  });

  it("an unexpected code shows its code, never its message", () => {
    for (const c of ["internal", "malformed_request", "malformed_response", "worker_failed", "encode_failed", "platform_unsupported", "some_future_code"]) {
      const r = classifyError(err(c, undefined, "SECRET-LOOKING-MESSAGE"));
      expect(r).toMatchObject({ route: "notice", kind: "error" });
      expect(JSON.stringify(r)).toContain(c);
      expect(JSON.stringify(r)).not.toContain("SECRET-LOOKING-MESSAGE");
    }
  });

  it("anything that is not a bridge error is a bug and says so without quoting it", () => {
    const r = classifyError(new TypeError("cannot read property 'value' of x: sk_live_do_not_show"));
    expect(r).toMatchObject({ route: "notice", kind: "error" });
    expect(JSON.stringify(r)).not.toContain("sk_live");
    expect(classifyError("a string")).toMatchObject({ route: "notice", kind: "error" });
    expect(classifyError(null)).toMatchObject({ route: "notice", kind: "error" });
    expect(errorCode(new Error("x"))).toBeNull();
  });

  it("a stub that is not wired yet is an info notice", () => {
    expect(classifyError(new NotWiredError("entry.create"))).toMatchObject({ route: "notice", kind: "info" });
  });
});

describe("routeError", () => {
  it("never swallows: every route reaches the user or the screen", () => {
    const codes = ["vault_locked", "node_locked", "two_factor_required", "presence_required", "approval_pending", "approval_denied", "conflict", "wrong_passphrase", "gate_verification_failed", "recovery_code_mismatch", "rate_limited", "node_access_denied", "capability_not_held", "entry_exists", "not_found", "vault_already_initialized", "broker_unreachable", "internal", "weird"];
    for (const c of codes) {
      const { h, log } = host();
      routeError(err(c), {}, h);
      expect(log.length, c).toBeGreaterThan(0);
    }
  });

  it("lock: the host clears and locks, with no notice on top", () => {
    const { h, log } = host();
    routeError(err("vault_locked"), {}, h);
    expect(log).toEqual([["lock", "vault_locked"]]);
  });

  it("an inline error is also raised as a notice until a screen renders it itself", () => {
    const a = host();
    routeError(err("wrong_passphrase"), { field: "passphrase" }, a.h);
    expect(a.log).toEqual([["inline", "passphrase", "Wrong passphrase."], ["notify", "error", "Wrong passphrase."]]);
    const b = host();
    routeError(err("wrong_passphrase"), { field: "passphrase", inlineRendered: true }, b.h);
    expect(b.log).toEqual([["inline", "passphrase", "Wrong passphrase."]]);
  });

  it("presence names the operation", () => {
    const { h, log } = host();
    routeError(err("presence_required"), { op: "grant.create" }, h);
    expect(log).toEqual([["notify", "presence", `${PRESENCE_TEXT} (grant.create)`]]);
  });

  it("refresh reloads and tells the user", () => {
    const { h, log } = host();
    routeError(err("conflict"), { node: "atlas" }, h);
    expect(log[0]).toEqual(["refresh", ["atlas"]]);
    expect(log[1]).toEqual(["notify", "warn", "Changed elsewhere. Reloaded; try again."]);
  });

  it("returns the route so a caller can branch on it (e.g. retry after the second factor)", () => {
    const { h } = host();
    expect(routeError(err("two_factor_required"), { op: "x" }, h)).toEqual({ route: "two-factor" });
  });
});

describe("the session's words (work package A)", () => {
  it("waitText rounds UP and changes unit, so the Unlock button never comes back early", () => {
    expect(waitText(0)).toBe("1 s");
    expect(waitText(29.2)).toBe("30 s");
    expect(waitText(119)).toBe("119 s");
    expect(waitText(120)).toBe("2 min");
    expect(waitText(121)).toBe("3 min");
    expect(waitText(3600)).toBe("60 min");
    expect(waitText(7200)).toBe("2 h");
    expect(waitText(7201)).toBe("3 h");
  });

  it("the Lock screen's reason is chosen by the code that ended the login; the user's own lock gives none", () => {
    expect(lockNoteFor("session_expired")).toBe("Your session ended. Unlock to continue.");
    expect(lockNoteFor("vault_locked")).toBe("The vault was locked. Unlock to continue.");
    expect(lockNoteFor("anything-else")).toBe("The vault was locked.");
    expect(lockNoteFor("")).toBe("");
    expect(lockNoteFor(null)).toBe("");
  });

  it("the last door never says which of its two factors was wrong; the login does say it was the passphrase", () => {
    expect(classifyError(err("wrong_passphrase"), { op: "vault.gate_recover" })).toMatchObject({ route: "inline", field: "recovery", message: "The passphrase or the recovery code is wrong." });
    expect(classifyError(err("wrong_passphrase"), { op: "vault.unlock" })).toMatchObject({ field: "passphrase", message: "Wrong passphrase." });
  });

  it("rate_limited carries the broker's wait out to the host so the screen can hold its buttons (bounded to a day)", () => {
    expect(classifyError(err("rate_limited", { retryAfterSeconds: 90 }))).toMatchObject({ retryAfterSeconds: 90, message: "Too many attempts. Try again in 90 s." });
    expect(classifyError(err("rate_limited", { retryAfterSeconds: 1800 }))).toMatchObject({ message: "Too many attempts. Try again in 30 min." });
    expect(classifyError(err("rate_limited", { retryAfterSeconds: 1e9 }))).toMatchObject({ retryAfterSeconds: 86400 });
    expect(classifyError(err("rate_limited", { retryAfterSeconds: -5 }))).toMatchObject({ retryAfterSeconds: 0 });
    expect(classifyError(err("rate_limited"))).not.toHaveProperty("retryAfterSeconds");
    const { h, log } = host();
    routeError(err("rate_limited", { retryAfterSeconds: 12 }), { field: "passphrase", inlineRendered: true }, h);
    expect(log).toEqual([["inline", "passphrase", "Too many attempts. Try again in 12 s.", { afterSeconds: 12 }]]);
  });

  it("a broker error code never reaches the user as the broker's own message (only a code the router knows how to word)", () => {
    for (const code of ["vault_locked", "session_expired", "wrong_passphrase", "gate_verification_failed", "recovery_code_mismatch", "two_factor_required"]) {
      expect(JSON.stringify(classifyError(err(code, undefined, "RAW-BROKER-TEXT-9f2")))).not.toContain("RAW-BROKER-TEXT-9f2");
    }
  });
});

describe("the fields of an entry (ADR-078)", () => {
  it("malformed_request means something the user can act on for the field operations, worded by operation; elsewhere it stays an unexpected error", () => {
    // adding or editing a field: next to the form, in the field's own words
    for (const op of ["field.add", "field.update"]) {
      expect(classifyError(err("malformed_request", undefined, "fields[0].label is longer than 200 characters"), { op, field: "field.save" })).toEqual({
        route: "inline",
        field: "field.save",
        message: "The broker did not accept that field. A label is one line of at most 200 characters. Nothing was changed.",
      });
    }
    // the last field cannot go
    expect(classifyError(err("malformed_request"), { op: "field.remove" })).toEqual({
      route: "notice",
      kind: "warn",
      message: "An entry keeps at least one field. Remove the entry instead. Nothing was changed.",
    });
    // a reorder that no longer matches the entry reloads it
    expect(classifyError(err("malformed_request"), { op: "field.reorder", node: "atlas" })).toMatchObject({ route: "refresh", nodes: ["atlas"] });
    expect(classifyError(err("malformed_request"), { op: "field.reorder" })).toMatchObject({ route: "refresh", nodes: [] });
    // B-11: a step-up with no gate enrolled is said plainly, not shown as a bug
    expect(classifyError(err("malformed_request"), { op: "vault.gate_verify" })).toEqual({ route: "notice", kind: "info", message: "No second factor is enrolled, so there is nothing to give. A node that asks for one is not asking anyone yet." });
    // any other operation: still a bug, with its code
    expect(classifyError(err("malformed_request"), { op: "entry.create" })).toEqual({ route: "notice", kind: "error", message: "Unexpected error (malformed_request). Nothing was changed." });
    expect(classifyError(err("malformed_request"))).toMatchObject({ route: "notice", kind: "error" });
    // and after a write that happened, the words are the after-write ones
    expect(classifyError(err("malformed_request"), { changed: "Saved." })).toMatchObject({ kind: "error", message: expect.stringContaining("Saved. The screen could not be refreshed (malformed_request)") });
  });

  it("the shell's own field codes are worded and say nothing of the entry or the value", () => {
    expect(classifyError(err("field_required", undefined, "this entry has 5 fields"))).toEqual({ route: "notice", kind: "warn", message: "This entry has several fields: choose the one to copy. Nothing was copied." });
    expect(classifyError(err("invalid_fields", undefined, "fields[2] has a value of the wrong type"))).toEqual({ route: "notice", kind: "warn", message: "That paste could not be previewed. Nothing was changed." });
    for (const code of ["field_required", "invalid_fields", "malformed_request"]) expect(JSON.stringify(classifyError(err(code, undefined, "RAW-9f2"), { op: "field.add" }))).not.toContain("RAW-9f2");
  });

  it("a stale generation or a field that is gone reloads, and hands the failed call's context to the host so the one entry can be re-read too", () => {
    const calls: Array<[string[], unknown]> = [];
    const h = { ...host().h, refresh: (nodes: string[], ctx?: unknown) => calls.push([nodes, ctx]) };
    const ctx = { op: "field.update", node: "atlas", entry: "e-a2", field: "field.save" };
    routeError(err("conflict", { node: "atlas", expectedGeneration: 1, currentGeneration: 4 }), ctx, h);
    routeError(err("not_found"), ctx, h);
    expect(calls).toEqual([[["atlas"], ctx], [["atlas"], ctx]]);
  });
});
