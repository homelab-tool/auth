import { test, expect } from "../fixtures";

test("register, login, and logout with OPAQUE", async ({ page, e2e }) => {
    await page.goto(`${e2e.authUrl}/register`);
    await page.fill("#clientId", "opaque-user");
    await page.fill("#password", "test-password");
    await page.fill("#confirm", "test-password");
    await page.click("#register-opaque-form button[type='submit']");

    await page.waitForSelector("[id='2fa-setup-section']", { state: "visible" });
    await page.click("#skip-2fa");
    await expect(page).toHaveURL(`${e2e.authUrl}/success`);
    await expect(page.locator("h1")).toHaveText("Logged in successfully!");

    await page.click("button:has-text('Log Out')");
    await expect(page).toHaveURL(`${e2e.authUrl}/login`);

    await page.fill("#clientId", "opaque-user");
    await page.fill("#password", "test-password");
    await page.click("#login-form button[type='submit']");
    await expect(page).toHaveURL(`${e2e.authUrl}/success`);
});
