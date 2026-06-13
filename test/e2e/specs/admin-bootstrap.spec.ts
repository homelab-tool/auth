import { test, expect } from "../fixtures";

test("admin user created on first start can login", async ({ page, e2e }) => {
    await test.step("login as admin", async () => {
        expect(e2e.adminUsername).toBe("admin");

        await page.goto(`${e2e.authUrl}/login`);
        await page.fill("#clientId", e2e.adminUsername);
        await page.fill("#password", e2e.adminPassword);
        await page.click("#login-form button[type='submit']");
        await expect(page).toHaveURL(`${e2e.authUrl}/profile`);
        await expect(page.locator("h1")).toHaveText("Profile");
        const dds = page.locator("dd");
        await expect(dds.nth(0)).toHaveText(e2e.adminUsername);
        await expect(dds.nth(1)).toHaveText("Password");
    });
});
