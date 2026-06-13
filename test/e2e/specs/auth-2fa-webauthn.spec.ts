import { test, expect } from "../fixtures";

test("enroll WebAuthn 2FA for OPAQUE user", async ({ page, e2e, context }) => {
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: {
            protocol: "ctap2",
            transport: "internal",
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
        },
    });

    const username = "webauthn2fa-user";
    const password = "test-password";

    await test.step("register and navigate to 2FA enrollment", async () => {
        await page.goto(`${e2e.authUrl}/register`);
        await page.fill("#clientId", username);
        await page.fill("#password", password);
        await page.fill("#confirm", password);
        await page.click("#register-opaque-form button[type='submit']");
        await expect(page.locator("#enrollment-section")).toBeVisible();
    });

    await test.step("set up WebAuthn security key", async () => {
        await page.click("#webauthn-2fa-setup");
        await expect(page.locator("#webauthn-2fa-status")).toContainText("successfully");
    });

    await test.step("verify WebAuthn shows as enabled on profile", async () => {
        await page.click("a:has-text('Skip for now')");
        await expect(page).toHaveURL(`${e2e.authUrl}/profile`);
        await expect(page.locator("#profile-2fa")).toContainText("Enabled");
    });
});
