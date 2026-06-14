import { test, expect } from "../fixtures";

test("admin user created on first start can login", async ({ page, app }) => {
    await test.step("login as admin", async () => {
        expect(app.adminUsername).toBe("admin");

        await page.goto(`${app.authUrl}/login`);
        await page.fill("#clientId", app.adminUsername);
        await page.fill("#password", app.adminPassword);
        await page.click("#login-form button[type='submit']");
        await expect(page).toHaveURL(`${app.authUrl}/profile`);
        await expect(page.locator("h1")).toHaveText("Profile");
        const dds = page.locator("dd");
        await expect(dds.nth(0)).toHaveText(app.adminUsername);
        await expect(dds.nth(1)).toHaveText("Password");
    });
});
