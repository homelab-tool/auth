import { test, expect } from "../fixtures";

test("enroll, verify TOTP required on login, then disable", async ({ page, e2e, totp }) => {
    const username = "totp-user";
    const password = "test-password";
    let secret: string | null = null;

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
        secret = await secretEl.textContent();
        expect(secret).toBeTruthy();

        const code = await totp.generate(secret!);
        expect(code).toBeTruthy();

        await page.fill("#totp-code", code);
        await page.click("button:has-text('Verify')");
        await expect(page.locator("#totp-section")).toContainText("successfully");
    });

    await test.step("go to profile and verify TOTP enabled", async () => {
        await page.click("a:has-text('Skip for now')");
        await expect(page).toHaveURL(`${e2e.authUrl}/profile`);
        await expect(page.locator("#profile-2fa")).toContainText("Enabled");
    });

    await test.step("logout", async () => {
        await page.click("button:has-text('Log Out')");
        await expect(page).toHaveURL(`${e2e.authUrl}/login`);
    });

    await test.step("login with password shows 2FA challenge", async () => {
        await page.fill("#clientId", username);
        await page.fill("#password", password);
        await page.click("#login-form button[type='submit']");

        await expect(page.locator("#login-2fa-section")).toBeVisible();
        await expect(page.locator("#totp-code")).toBeVisible();
    });

    await test.step("complete login with TOTP code", async () => {
        const code = await totp.generate(secret!);
        await page.fill("#totp-code", code);
        await page.click("#login-2fa-section button[type='submit']");

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
