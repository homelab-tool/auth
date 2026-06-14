import { test, expect } from "../fixtures";
import { LoginPage } from "../pages/LoginPage";
import { RegisterPage } from "../pages/RegisterPage";
import { ProfilePage } from "../pages/ProfilePage";
import { setupVirtualAuthenticator } from "../pages/WebAuthnHelper";

test("register, logout and login with passkey", async ({ page, app, context }) => {
    await setupVirtualAuthenticator(context, page);

    const register = new RegisterPage(page, app.authUrl);
    const profile = new ProfilePage(page, app.authUrl);

    await test.step("register", async () => {
        await register.goto();
        await register.displayName.fill("Passkey User");
        await register.webauthnSubmitButton.click();
        await expect(register.enrollmentSection).toBeVisible();
        await register.continueToProfileLink.click();
        await expect(page).toHaveURL(`${app.authUrl}/profile`);
        await expect(profile.heading).toHaveText("Profile");
        await expect(profile.detailItems.nth(0)).toHaveText("Passkey User");
        await expect(profile.detailItems.nth(1)).toHaveText("Passkey");
    });

    await test.step("logout", async () => {
        await profile.logoutButton.click();
        await expect(page).toHaveURL(`${app.authUrl}/login`);
    });

    await test.step("login", async () => {
        const login = new LoginPage(page, app.authUrl);
        await login.goto();
        await login.passkeyButton.click();
        await expect(page).toHaveURL(`${app.authUrl}/profile`);
        await expect(profile.heading).toHaveText("Profile");
    });
});
