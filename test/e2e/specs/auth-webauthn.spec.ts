import { test, expect } from "../fixtures";

test("register and login with passkey", async ({ page, e2e, context }) => {
    await page.goto(`${e2e.authUrl}/register`);

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

    await page.fill("#webauthn-displayName", "Passkey User");
    await page.click("#register-webauthn-form button[type='submit']");
    await expect(page).toHaveURL(`${e2e.authUrl}/profile`);
    await expect(page.locator("h1")).toHaveText("Profile");

    const dds = page.locator("dd");
    await expect(dds.nth(0)).toHaveText("Passkey User");
    await expect(dds.nth(1)).toHaveText("Passkey");

    await page.goto(`${e2e.authUrl}/login`);

    await page.click("#passkey-login");
    await expect(page).toHaveURL(`${e2e.authUrl}/profile`);
    await expect(page.locator("h1")).toHaveText("Profile");
});
