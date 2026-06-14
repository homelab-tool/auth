import { test, expect } from "../fixtures";

test("register, logout and login with OPAQUE", async ({ page, app }) => {
    await test.step("register", async () => {
        await page.goto(`${app.authUrl}/register`);

        await page.fill("#clientId", "opaque-user");
        await page.fill("#password", "test-password");
        await page.fill("#confirm", "test-password");
        await page.click("#register-opaque-form button[type='submit']");

        await expect(page.locator("#enrollment-section")).toBeVisible();
        await page.click("a:has-text('Skip for now')");
        await expect(page).toHaveURL(`${app.authUrl}/profile`);

        await expect(page.locator("h1")).toHaveText("Profile");
        const dds = page.locator("dd");
        await expect(dds.nth(0)).toHaveText("opaque-user");
        await expect(dds.nth(1)).toHaveText("Password");
    });

    await test.step("logout", async () => {
        await page.click("button:has-text('Log Out')");
        await expect(page).toHaveURL(`${app.authUrl}/login`);
    });

    await test.step("login", async () => {
        await page.fill("#clientId", "opaque-user");
        await page.fill("#password", "test-password");
        await page.click("#login-form button[type='submit']");
        await expect(page).toHaveURL(`${app.authUrl}/profile`);
        await expect(page.locator("h1")).toHaveText("Profile");
    });
});
