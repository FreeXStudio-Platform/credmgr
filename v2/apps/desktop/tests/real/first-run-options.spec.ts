/**
 * First-run choices against a real broker: the passphrase floor is four characters (eight is only recommended), and the recovery
 * code can be skipped (the code shown is what is confirmed). Nothing here is a fixture's idea of what the broker accepts.
 */
import { expect, test } from "./harness";
import { KDF, lockUi, passInput, unlockButton } from "./helpers";

test("a four-character passphrase with the recovery code skipped and no second factor creates a real vault that locks and unlocks", async ({ app }) => {
  const { page } = app;
  const short = "abcd";
  await app.open();
  await expect(app.screen("S17 First run")).toBeVisible();
  await page.getByPlaceholder("passphrase", { exact: true }).fill(short);
  await page.getByPlaceholder("repeat it").fill(short);
  await expect(page.getByText("Short passphrases are easier to guess. 8 or more is recommended")).toBeVisible();
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.getByText("first run · step 2 of 4")).toBeVisible(KDF);

  // nothing retyped, nothing ticked: "Skip for now" confirms the code that is on screen
  await page.getByRole("button", { name: "Skip for now", exact: true }).click();
  await expect(page.getByText("first run · step 3 of 4")).toBeVisible(KDF);
  await page.getByRole("button", { name: "Enrol later", exact: true }).click();
  await page.getByRole("button", { name: "Open the vault", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);

  // the vault the broker wrote opens with that passphrase and no other
  await lockUi(app);
  await passInput(app).fill("abce");
  await unlockButton(app).click();
  await expect(page.getByRole("alert")).toBeVisible(KDF);
  await passInput(app).fill(short);
  await unlockButton(app).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
});
