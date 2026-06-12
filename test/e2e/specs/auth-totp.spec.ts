import { test, expect } from "../fixtures";

test("register with TOTP and login with 2FA", async ({ page, e2e, totp }) => {
    await page.goto(`${e2e.authUrl}/register`);
    await page.fill("#clientId", "totp-user");
    await page.fill("#password", "test-password");
    await page.fill("#confirm", "test-password");
    await page.click("#register-opaque-form button[type='submit']");
    await page.waitForSelector("[id='2fa-setup-section']", { state: "visible" });

    await page.click("#totp-setup");
    const secret = await page.textContent("#totp-secret");
    const code = await totp.generate(secret!.trim());
    await page.fill("#totp-setup-code", code);
    await page.click("#totp-verify-form button[type='submit']");
    await expect(page).toHaveURL(`${e2e.authUrl}/success`);

    await page.click("button:has-text('Log Out')");
    await expect(page).toHaveURL(`${e2e.authUrl}/login`);

    await page.fill("#clientId", "totp-user");
    await page.fill("#password", "test-password");
    await page.click("#login-form button[type='submit']");
    await page.waitForSelector("[id='2fa-section']", { state: "visible" });

    const code2 = await totp.generate(secret!.trim());
    await page.fill("#totp-code", code2);
    await page.click("#totp-form button[type='submit']");
    await expect(page).toHaveURL(`${e2e.authUrl}/success`);
});
