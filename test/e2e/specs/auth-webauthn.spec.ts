import { test, expect } from "../fixtures";

test("register, logout and login with passkey", async ({ page, e2e, context }) => {
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

    await test.step("register", async () => {
        await page.goto(`${e2e.authUrl}/register`);

        await page.fill("#webauthn-displayName", "Passkey User");
        await page.click("#register-webauthn-form button[type='submit']");

        await expect(page.locator("#enrollment-section")).toBeVisible();
        await page.click("a:has-text('Skip for now')");
        await expect(page).toHaveURL(`${e2e.authUrl}/profile`);

        await expect(page.locator("h1")).toHaveText("Profile");
        const dds = page.locator("dd");
        await expect(dds.nth(0)).toHaveText("Passkey User");
        await expect(dds.nth(1)).toHaveText("Passkey");
    });

    await test.step("logout", async () => {
        await page.click("button:has-text('Log Out')");
        await expect(page).toHaveURL(`${e2e.authUrl}/login`);
    });

    await test.step("login", async () => {
        await page.click("#passkey-login");
        await expect(page).toHaveURL(`${e2e.authUrl}/profile`);
        await expect(page.locator("h1")).toHaveText("Profile");
    });
});
