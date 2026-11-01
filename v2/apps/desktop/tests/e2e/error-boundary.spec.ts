/**
 * A render exception must show a visible error screen, never a blank window.
 *
 * The first version of the host put its error boundary inside the component whose own render() throws, which React never
 * catches (a boundary catches only what its CHILDREN throw): a throwing renderVals() left an empty window.  The boundary now
 * sits above the host (src/main.ts, src/dc/runtime.ts DCBoundary).  These specs make the logic throw and look at the page.
 */
import { expect, test } from "./harness";

test("a throwing renderVals() shows the error screen, not a blank window", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: false }); // the demo data: no shell needed
  await expect(app.screen("S1 Main")).toBeVisible();
  expect(await page.locator("#dc-root").innerHTML()).not.toBe("");

  app.expectConsoleError(/^CredMgr render error: render boom$/);
  await page.evaluate(() => {
    const cm = (window as any).__cm;
    cm.renderVals = () => {
      throw new Error("render boom");
    };
    cm.setState({ tick: 1 }); // any state change re-renders the host
  });

  const panel = page.getByRole("alert");
  await expect(panel).toHaveText("Something went wrong. Restart CredMgr.");
  await expect(panel).toHaveAttribute("data-error-boundary", "true");
  // the window is not blank: the host element is there and holds the panel, and the app screens are gone
  expect(await page.locator("#dc-root .sc-host").count()).toBe(1);
  expect(await page.locator("#dc-root").innerHTML()).toContain("Something went wrong");
  await expect(page.locator("[data-screen-label]")).toHaveCount(0);
});

test("an exception thrown while the template renders is caught the same way", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: false });
  await expect(app.screen("S1 Main")).toBeVisible();

  app.expectConsoleError(/^CredMgr render error: template boom$/);
  await page.evaluate(() => {
    const cm = (window as any).__cm;
    const real = cm.renderVals.bind(cm);
    // a value the template prints (`node · {{inspLabel}}`) whose conversion to text throws: the failure happens inside the compiled template
    cm.renderVals = () => ({
      ...real(),
      inspLabel: {
        toString() {
          throw new Error("template boom");
        },
      },
    });
    cm.setState({ tick: 2 });
  });
  await expect(page.getByRole("alert")).toHaveText("Something went wrong. Restart CredMgr.");
});

test("the error screen logs the message only, never state", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: false });
  await expect(app.screen("S1 Main")).toBeVisible();
  app.expectConsoleError(/CredMgr render error/);
  await page.evaluate(() => {
    const cm = (window as any).__cm;
    cm.state.searchQ = "secret-looking-search-term";
    cm.renderVals = () => {
      throw new Error("boom with no state");
    };
    cm.setState({ tick: 3 });
  });
  await expect(page.getByRole("alert")).toBeVisible();
  expect(app.consoleErrors).toEqual(["CredMgr render error: boom with no state"]);
  for (const line of app.consoleErrors) expect(line).not.toContain("secret-looking-search-term");
  app.consoleErrors.length = 0; // consumed: asserted just above
});
