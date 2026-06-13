import { test, expect } from "../fixtures";

test("enroll TOTP 2FA for OPAQUE user", async ({ page, e2e, totp }) => {
    const username = "totp-user";
    const password = "test-password";

    await test.step("register and navigate to 2FA enrollment", async () => {
        await page.goto(`${e2e.authUrl}/register`);
        await page.fill("#clientId", username);
        await page.fill("#password", password);
        await page.fill("#confirm", password);
        await page.click("#register-opaque-form button[type='submit']");
        await expect(page.locator("#enrollment-section")).toBeVisible();
    });

    await test.step("set up TOTP authenticator app", async () => {
        await page.click("button:has-text('Set Up Authenticator App')");

        const secretEl = page.locator("#totp-section code");
        await expect(secretEl).toBeVisible();
        const secret = await secretEl.textContent();
        expect(secret).toBeTruthy();

        const code = await totp.generate(secret!);
        expect(code).toBeTruthy();

        await page.fill("#totp-code", code);
        await page.click("button:has-text('Verify')");
        await expect(page.locator("#totp-section")).toContainText("successfully");
    });

    await test.step("verify TOTP shows as enabled on profile", async () => {
        await page.click("a:has-text('Skip for now')");
        await expect(page).toHaveURL(`${e2e.authUrl}/profile`);
        await expect(page.locator("#profile-2fa")).toContainText("Enabled");
    });

    await test.step("disable TOTP via API and verify", async () => {
        const cookies = await page.context().cookies();
        const token = cookies.find((c) => c.name === "token");
        expect(token).toBeDefined();

        const resp = await page.request.delete(`${e2e.authUrl}/api/opaque/register/2fa/totp`, {
            headers: { Authorization: `Bearer ${token!.value}` },
        });
        expect(resp.status()).toBe(200);

        await page.reload();
        await expect(page.locator("#profile-2fa")).toContainText("Not set up");
    });
});
