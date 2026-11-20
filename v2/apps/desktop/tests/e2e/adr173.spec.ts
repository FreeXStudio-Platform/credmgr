/**
 * ADR-173, the window's half, driven against the fixture broker:
 *
 *   locked decision   with a presence key enrolled the Lock screen's Approve still takes the passphrase (and code) and sends no presence proof: the unlock
 *                     factors authorise a decision on a locked vault (ADR-088), and a key changes nothing there
 *   deny              a denial is never gated
 *   login decision    from a login, approving is `presence_required` once a key is enrolled (the real shell attaches the proof and retries; the page sees none
 *                     of it) and denying is not
 *
 * The notification, the menu-bar count and the Dock bounce are the shell's (`src-tauri/src/approval_notify.rs`, tested in Rust) and are not pressed in a
 * browser; `docs/RELEASE_VERIFICATION.md` lists them as "not pressed". The real-broker proof of the presence rule is `crates/brokerd/tests/presence.rs`.
 */
import { FIXTURE_PASSPHRASE } from "../fixtures/broker/index";
import { expect, test, type App } from "./harness";

const panel = (app: App) => app.screen("S16a Locked approval");

test.describe("agent requests, with a presence key enrolled", () => {
  test("the locked Approve is unchanged: the passphrase decides it and no presence proof is sent or asked for", async ({ app }) => {
    const broker = (await app.open({
      broker: { locked: true, presenceKey: true, approvals: { rq_one: { node: "atlas", entry: "e-a1" } } },
    }))!;
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    await app.page.getByRole("button", { name: "1 agent request is waiting for approval" }).click();
    await expect(panel(app)).toBeVisible();
    await panel(app).getByLabel("passphrase for this decision").fill(FIXTURE_PASSPHRASE);
    await panel(app).getByRole("button", { name: "Approve" }).click();
    expect((await broker.calls("vault_approval_decide"))[0].args).toEqual({ request: "rq_one", approved: true, passphrase: FIXTURE_PASSPHRASE });
    await expect(app.page.getByText("approved with the passphrase · the vault is still locked")).toBeVisible();
    // The page never asked for a presence challenge: that is the shell's, and only for a decision from a login.
    expect((await broker.calls("presence_challenge")).length).toBe(0);
  });

  test("the locked Deny is unchanged too", async ({ app }) => {
    const broker = (await app.open({
      broker: { locked: true, presenceKey: true, approvals: { rq_one: { node: "atlas", entry: "e-a1" } } },
    }))!;
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    await app.page.getByRole("button", { name: "1 agent request is waiting for approval" }).click();
    await panel(app).getByLabel("passphrase for this decision").fill(FIXTURE_PASSPHRASE);
    await panel(app).getByRole("button", { name: "Deny" }).click();
    expect((await broker.calls("vault_approval_decide"))[0].args).toEqual({ request: "rq_one", approved: false, passphrase: FIXTURE_PASSPHRASE });
  });

  test("from a login, approving needs the proof the shell attaches and denying does not (the fixture answers as the broker does)", async ({ app }) => {
    const broker = (await app.open({
      broker: { locked: false, presenceKey: true, approvals: { rq_one: { node: "atlas", entry: "e-a1" } } },
    }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    const decide = (approved: boolean) =>
      app.page.evaluate(
        async (a) => {
          try {
            return { ok: await (window as any).__TAURI_INTERNALS__.invoke("vault_approval_decide", { request: "rq_one", approved: a }) };
          } catch (e: any) {
            return { code: e.code };
          }
        },
        approved,
      );
    expect(await decide(true)).toEqual({ code: "presence_required" });
    expect(await decide(false)).toMatchObject({ ok: { request: "rq_one", approved: false } });
    expect((await broker.calls("vault_approval_decide")).length).toBe(2);
  });
});
