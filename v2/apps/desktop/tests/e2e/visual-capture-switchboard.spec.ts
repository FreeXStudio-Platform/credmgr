/**
 * Visual capture for the switchboard (not a regression spec; run it with scripts/visual-capture.sh <dir>): skipped unless CREDMGR_SHOTS is set.
 * No page.screenshot (in WebKit it injects a <style>, which the CSP refuses): Playwright's video screencast records the
 * page without touching the DOM; each capture point holds still and is noted as a time offset, and ffmpeg pulls that frame.
 */
import * as fs from "node:fs";
import { expect, test, type App } from "./harness";
import { openSettings } from "./wp-d-helpers";

const DIR = process.env.CREDMGR_SHOTS;
test.skip(!DIR, "visual capture only");

const SHORT = { id: "app.autoLockMins", from: 15, to: 60, reason: "the agent wants longer sessions", cwd: "/work/fixture-project" };
const LONG = {
  id: "vault.confirmBeforeReveal.windowSeconds", from: 300, to: 3600,
  reason: "The user asked me to stop being prompted so often while running the long database migration this afternoon; they said an hour is fine for today and they will turn it back afterwards. ".repeat(2).trim(),
  cwd: "/srv/work/clients/acme-holdings/projects/an-unusually-long-project-folder-name/services/payments-gateway/infrastructure/terraform/environments/production-eu-west-1",
};
const NODE = { id: "node.securityLevel", node: "atlas", from: "guarded", to: "open", reason: "user wants no approvals on atlas", cwd: "/work/atlas" };

const label = process.env.CREDMGR_SHOTS_SIZE === "narrow" ? "narrow" : "1440";
const size = label === "narrow" ? { width: 640, height: 480 } : { width: 1440, height: 900 };
test.use({ viewport: size, video: { mode: "on", size } });
{
  {
    for (const theme of ["light", "dark"] as const) {
      for (const [count, reqs] of [["1", [SHORT]], ["3", [SHORT, LONG, NODE]]] as const) {
        test(`requests ${count} ${theme} ${label}`, async ({ app }, info) => {
          const t0 = Date.now();
          const marks: Record<string, number> = {};
          const mark = async (name: string) => { await app.page.waitForTimeout(700); marks[name] = (Date.now() - t0) / 1000; await app.page.waitForTimeout(700); };
          await app.open({ broker: { locked: false, settings: { "app.theme": theme }, settingRequests: reqs as any } });
          await expect(app.screen("S1 Main")).toBeVisible();
          await openSettings(app, "Agents");
          const list = app.screen("S21b Requests from agents");
          await expect(list).toBeVisible();
          await expect.poll(() => app.page.evaluate(() => document.documentElement.dataset.theme)).toBe(theme);
          await list.scrollIntoViewIfNeeded();
          await mark(`requests-${count}-${theme}-${label}`);
          if (count === "3") {
            await list.evaluate((el) => el.scrollIntoView({ block: "end" }));
            await mark(`requests-${count}-${theme}-${label}-end`);
          }
          if (count === "1") {
            await list.locator('[data-setting-request="srq-1"]').getByRole("button", { name: /^approve/ }).click();
            await expect(app.screen("Confirm it is you")).toBeVisible();
            await mark(`confirm-${theme}-${label}`);
          }
          await app.page.close();
          const video = `${DIR}/${info.title.replace(/ /g, "_")}.webm`;
          await app.page.video()!.saveAs(video);
          fs.writeFileSync(`${DIR}/${info.title.replace(/ /g, "_")}.json`, JSON.stringify({ video, marks }));
        });
      }
    }
  }
}
